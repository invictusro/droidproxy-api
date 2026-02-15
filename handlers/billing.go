package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
)

// DepositRequest represents a request to add funds
type DepositRequest struct {
	Amount int64 `json:"amount" binding:"required,min=1000"` // Amount in cents, minimum $10
}

// DepositResponse contains the checkout URL
type DepositResponse struct {
	CheckoutURL string `json:"checkout_url"`
	Amount      int64  `json:"amount"`
}

// BillingProfileResponse represents the user's billing profile
type BillingProfileResponse struct {
	BillingName    string `json:"billing_name"`
	BillingCUI     string `json:"billing_cui"`
	BillingRegCom  string `json:"billing_reg_com"`
	BillingAddress string `json:"billing_address"`
	BillingCity    string `json:"billing_city"`
	BillingCounty  string `json:"billing_county"`
	BillingCountry string `json:"billing_country"`
}

// BillingProfileRequest represents a request to update billing profile
type BillingProfileRequest struct {
	BillingName    string `json:"billing_name"`
	BillingCUI     string `json:"billing_cui"`
	BillingRegCom  string `json:"billing_reg_com"`
	BillingAddress string `json:"billing_address"`
	BillingCity    string `json:"billing_city"`
	BillingCounty  string `json:"billing_county"`
	BillingCountry string `json:"billing_country"`
}

// BillingSettingsResponse represents user billing settings
type BillingSettingsResponse struct {
	BillingDay        *int   `json:"billing_day"`
	AutoRefillEnabled bool   `json:"auto_refill_enabled"`
	HasPaymentMethod  bool   `json:"has_payment_method"`
	DefaultCardLast4  string `json:"default_card_last4,omitempty"`
}

// BillingSettingsRequest represents a request to update billing settings
type BillingSettingsRequest struct {
	AutoRefillEnabled *bool `json:"auto_refill_enabled"`
}

// CreateDeposit creates a Stripe Checkout session for balance deposit
// POST /billing/deposit
func CreateDeposit(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var req DepositRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Amount must be at least $10 (1000 cents)"})
		return
	}

	stripe.Key = config.AppConfig.StripeSecretKey

	// Get or create Stripe customer
	stripeCustomerID, err := getOrCreateStripeCustomer(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create payment session"})
		return
	}

	// Create Checkout Session with full billing features
	params := &stripe.CheckoutSessionParams{
		Customer: stripe.String(stripeCustomerID),
		Mode:     stripe.String(string(stripe.CheckoutSessionModePayment)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String("usd"),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name:        stripe.String("DroidProxy Balance Deposit"),
						Description: stripe.String(fmt.Sprintf("Add $%.2f to your balance", float64(req.Amount)/100)),
					},
					UnitAmount: stripe.Int64(req.Amount),
				},
				Quantity: stripe.Int64(1),
			},
		},
		// Save card for future off-session charges
		PaymentIntentData: &stripe.CheckoutSessionPaymentIntentDataParams{
			SetupFutureUsage: stripe.String(string(stripe.PaymentIntentSetupFutureUsageOffSession)),
			Metadata: map[string]string{
				"user_id": user.ID.String(),
				"type":    "balance_deposit",
				"amount":  fmt.Sprintf("%d", req.Amount),
			},
		},
		// Collect billing address (required for VAT)
		BillingAddressCollection: stripe.String(string(stripe.CheckoutSessionBillingAddressCollectionRequired)),
		// Collect Tax ID (CUI/VAT)
		TaxIDCollection: &stripe.CheckoutSessionTaxIDCollectionParams{
			Enabled: stripe.Bool(true),
		},
		// Enable automatic tax calculation (VAT)
		AutomaticTax: &stripe.CheckoutSessionAutomaticTaxParams{
			Enabled: stripe.Bool(true),
		},
		// Generate invoice on successful payment
		InvoiceCreation: &stripe.CheckoutSessionInvoiceCreationParams{
			Enabled: stripe.Bool(true),
			InvoiceData: &stripe.CheckoutSessionInvoiceCreationInvoiceDataParams{
				Description: stripe.String(fmt.Sprintf("DroidProxy Balance Deposit - $%.2f", float64(req.Amount)/100)),
				Metadata: map[string]string{
					"user_id": user.ID.String(),
					"type":    "balance_deposit",
				},
			},
		},
		// Customer update settings - save billing details
		CustomerUpdate: &stripe.CheckoutSessionCustomerUpdateParams{
			Address: stripe.String("auto"),
			Name:    stripe.String("auto"),
		},
		SuccessURL: stripe.String(config.AppConfig.FrontendURL + "/billing?deposit=success"),
		CancelURL:  stripe.String(config.AppConfig.FrontendURL + "/billing?deposit=cancelled"),
		Metadata: map[string]string{
			"user_id": user.ID.String(),
			"type":    "balance_deposit",
			"amount":  fmt.Sprintf("%d", req.Amount),
		},
	}

	s, err := session.New(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create checkout session: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, DepositResponse{
		CheckoutURL: s.URL,
		Amount:      req.Amount,
	})
}

// GetBillingProfile returns the user's billing profile
// GET /billing/profile
func GetBillingProfile(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	c.JSON(http.StatusOK, BillingProfileResponse{
		BillingName:    user.BillingName,
		BillingCUI:     user.BillingCUI,
		BillingRegCom:  user.BillingRegCom,
		BillingAddress: user.BillingAddress,
		BillingCity:    user.BillingCity,
		BillingCounty:  user.BillingCounty,
		BillingCountry: user.BillingCountry,
	})
}

// UpdateBillingProfile updates the user's billing profile
// PUT /billing/profile
func UpdateBillingProfile(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var req BillingProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{
		"billing_name":    req.BillingName,
		"billing_cui":     req.BillingCUI,
		"billing_reg_com": req.BillingRegCom,
		"billing_address": req.BillingAddress,
		"billing_city":    req.BillingCity,
		"billing_county":  req.BillingCounty,
		"billing_country": req.BillingCountry,
	}

	if err := database.DB.Model(user).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update billing profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Billing profile updated"})
}

// GetBillingSettings returns the user's billing settings
// GET /billing/settings
func GetBillingSettings(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	// Check if user has a default payment method
	var defaultMethod models.PaymentMethod
	hasPaymentMethod := false
	defaultCardLast4 := ""

	if err := database.DB.Where("user_id = ? AND is_default = ?", user.ID, true).First(&defaultMethod).Error; err == nil {
		hasPaymentMethod = true
		defaultCardLast4 = defaultMethod.CardLast4
	}

	c.JSON(http.StatusOK, BillingSettingsResponse{
		BillingDay:        user.BillingDay,
		AutoRefillEnabled: user.AutoRefillEnabled,
		HasPaymentMethod:  hasPaymentMethod,
		DefaultCardLast4:  defaultCardLast4,
	})
}

// UpdateBillingSettings updates the user's billing settings
// PUT /billing/settings
func UpdateBillingSettings(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var req BillingSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := make(map[string]interface{})

	if req.AutoRefillEnabled != nil {
		updates["auto_refill_enabled"] = *req.AutoRefillEnabled
	}

	if len(updates) > 0 {
		if err := database.DB.Model(user).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update billing settings"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Billing settings updated"})
}

// GetBillingOverview returns a comprehensive billing overview
// GET /billing
func GetBillingOverview(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	// Get default payment method
	var defaultMethod models.PaymentMethod
	hasPaymentMethod := false
	var cardInfo *models.PaymentMethodResponse

	if err := database.DB.Where("user_id = ? AND is_default = ?", user.ID, true).First(&defaultMethod).Error; err == nil {
		hasPaymentMethod = true
		resp := defaultMethod.ToResponse()
		cardInfo = &resp
	}

	// Calculate monthly burn (sum of phone prices with auto_extend=true)
	var monthlyBurn int64
	var phones []models.Phone
	database.DB.Where("user_id = ? AND license_expires_at > ? AND auto_extend = ?", user.ID, time.Now(), true).Find(&phones)

	// Get plan prices
	planPrices := map[string]int64{
		"lite":  500,  // $5
		"turbo": 700,  // $7
		"nitro": 900,  // $9
	}

	for _, phone := range phones {
		if price, ok := planPrices[phone.PlanTier]; ok {
			monthlyBurn += price
		}
	}

	// Recent transactions
	var transactions []models.BalanceTransaction
	database.DB.Where("user_id = ?", user.ID).
		Order("created_at DESC").
		Limit(5).
		Find(&transactions)

	var recentTransactions []models.TransactionResponse
	for _, t := range transactions {
		recentTransactions = append(recentTransactions, t.ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"balance":             user.Balance,
		"balance_formatted":   fmt.Sprintf("$%.2f", float64(user.Balance)/100),
		"billing_day":         user.BillingDay,
		"auto_refill_enabled": user.AutoRefillEnabled,
		"has_payment_method":  hasPaymentMethod,
		"default_card":        cardInfo,
		"monthly_burn":        monthlyBurn,
		"monthly_burn_formatted": fmt.Sprintf("$%.2f", float64(monthlyBurn)/100),
		"phones_with_auto_extend": len(phones),
		"recent_transactions": recentTransactions,
		"billing_profile": BillingProfileResponse{
			BillingName:    user.BillingName,
			BillingCUI:     user.BillingCUI,
			BillingRegCom:  user.BillingRegCom,
			BillingAddress: user.BillingAddress,
			BillingCity:    user.BillingCity,
			BillingCounty:  user.BillingCounty,
			BillingCountry: user.BillingCountry,
		},
	})
}
