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
	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
)

// GetBalance returns the current user's balance
func GetBalance(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	response := models.BalanceResponse{
		Balance:          user.Balance,
		BalanceFormatted: fmt.Sprintf("$%.2f", float64(user.Balance)/100),
		UpdatedAt:        user.BalanceUpdatedAt,
	}

	c.JSON(http.StatusOK, response)
}

// GetBalanceTransactions returns the transaction history for the current user
func GetBalanceTransactions(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var transactions []models.BalanceTransaction
	if err := database.DB.Where("user_id = ?", user.ID).
		Order("created_at DESC").
		Limit(100).
		Find(&transactions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch transactions"})
		return
	}

	// Convert to response format
	var responses []models.TransactionResponse
	for _, t := range transactions {
		responses = append(responses, t.ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{"transactions": responses})
}

// AdminAdjustBalance allows admins to add or deduct user balance
func AdminAdjustBalance(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req models.AdminBalanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Amount must be positive"})
		return
	}

	// Find user
	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Determine transaction type
	var transactionType models.TransactionType
	var reason models.TransactionReason
	var balanceChange int64

	if req.Type == "credit" {
		transactionType = models.TransactionCredit
		reason = models.ReasonAdminCredit
		balanceChange = req.Amount
	} else {
		transactionType = models.TransactionDebit
		reason = models.ReasonAdminDebit
		balanceChange = -req.Amount

		// Check if user has enough balance
		if user.Balance+balanceChange < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient balance"})
			return
		}
	}

	// Start transaction
	tx := database.DB.Begin()

	// Update balance
	now := time.Now()
	if err := tx.Model(&user).Updates(map[string]interface{}{
		"balance":            user.Balance + balanceChange,
		"balance_updated_at": now,
	}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update balance"})
		return
	}

	// Create transaction record
	transaction := models.BalanceTransaction{
		UserID:      userID,
		Type:        transactionType,
		Amount:      req.Amount,
		Reason:      reason,
		Description: req.Description,
		CreatedAt:   now,
	}

	if err := tx.Create(&transaction).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create transaction record"})
		return
	}

	tx.Commit()

	c.JSON(http.StatusOK, gin.H{
		"message":     "Balance updated",
		"new_balance": user.Balance + balanceChange,
		"transaction": transaction.ToResponse(),
	})
}

// CreateTopUp creates a Stripe Checkout session for balance top-up
func CreateTopUp(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var req models.TopUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Handle crypto (placeholder)
	if req.PaymentMethod == "crypto" {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "Crypto payments coming soon"})
		return
	}

	// Stripe payment flow
	stripe.Key = config.AppConfig.StripeSecretKey

	// Get or create Stripe customer
	stripeCustomerID, err := getOrCreateStripeCustomer(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create payment session"})
		return
	}

	// Create Checkout Session with setup_intent for saving card
	params := &stripe.CheckoutSessionParams{
		Customer: stripe.String(stripeCustomerID),
		Mode:     stripe.String(string(stripe.CheckoutSessionModePayment)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String("usd"),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name:        stripe.String("DroidProxy Balance Top-Up"),
						Description: stripe.String(fmt.Sprintf("Add $%.2f to your balance", float64(req.Amount)/100)),
					},
					UnitAmount: stripe.Int64(req.Amount),
				},
				Quantity: stripe.Int64(1),
			},
		},
		PaymentIntentData: &stripe.CheckoutSessionPaymentIntentDataParams{
			SetupFutureUsage: stripe.String(string(stripe.PaymentIntentSetupFutureUsageOffSession)),
			Metadata: map[string]string{
				"user_id": user.ID.String(),
				"type":    "balance_topup",
				"amount":  fmt.Sprintf("%d", req.Amount),
			},
		},
		SuccessURL: stripe.String(config.AppConfig.FrontendURL + "/dashboard?topup=success"),
		CancelURL:  stripe.String(config.AppConfig.FrontendURL + "/dashboard?topup=cancelled"),
		Metadata: map[string]string{
			"user_id": user.ID.String(),
			"type":    "balance_topup",
			"amount":  fmt.Sprintf("%d", req.Amount),
		},
	}

	s, err := session.New(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create checkout session"})
		return
	}

	c.JSON(http.StatusOK, models.TopUpResponse{
		PaymentURL: s.URL,
		Amount:     req.Amount,
		Status:     "pending",
	})
}

// getOrCreateStripeCustomer returns existing or creates new Stripe customer
func getOrCreateStripeCustomer(user *models.User) (string, error) {
	stripe.Key = config.AppConfig.StripeSecretKey

	// If user already has a Stripe customer ID, return it
	if user.StripeCustomerID != "" {
		return user.StripeCustomerID, nil
	}

	// Create new Stripe customer
	params := &stripe.CustomerParams{
		Email: stripe.String(user.Email),
		Name:  stripe.String(user.Name),
		Metadata: map[string]string{
			"user_id": user.ID.String(),
		},
	}

	c, err := customer.New(params)
	if err != nil {
		return "", err
	}

	// Save to database
	if err := database.DB.Model(user).Update("stripe_customer_id", c.ID).Error; err != nil {
		return "", err
	}

	return c.ID, nil
}

// GetPaymentMethods returns saved payment methods for the current user
func GetPaymentMethods(c *gin.Context) {
	user := middleware.GetCurrentUser(c)

	var methods []models.PaymentMethod
	if err := database.DB.Where("user_id = ?", user.ID).
		Order("is_default DESC, created_at DESC").
		Find(&methods).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch payment methods"})
		return
	}

	var responses []models.PaymentMethodResponse
	for _, m := range methods {
		responses = append(responses, m.ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{"payment_methods": responses})
}

// DeletePaymentMethod removes a saved payment method
func DeletePaymentMethod(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	methodID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payment method ID"})
		return
	}

	var method models.PaymentMethod
	if err := database.DB.Where("id = ? AND user_id = ?", methodID, user.ID).First(&method).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Payment method not found"})
		return
	}

	// Delete from Stripe first (detach from customer)
	stripe.Key = config.AppConfig.StripeSecretKey
	// Note: We just delete from our DB, Stripe will handle cleanup
	// For full cleanup, use paymentmethod.Detach

	if err := database.DB.Delete(&method).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete payment method"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Payment method deleted"})
}

// SetDefaultPaymentMethod sets a payment method as the default
func SetDefaultPaymentMethod(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	methodID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payment method ID"})
		return
	}

	var method models.PaymentMethod
	if err := database.DB.Where("id = ? AND user_id = ?", methodID, user.ID).First(&method).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Payment method not found"})
		return
	}

	// Start transaction
	tx := database.DB.Begin()

	// Unset all other defaults
	if err := tx.Model(&models.PaymentMethod{}).
		Where("user_id = ?", user.ID).
		Update("is_default", false).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update payment method"})
		return
	}

	// Set this one as default
	if err := tx.Model(&method).Update("is_default", true).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update payment method"})
		return
	}

	tx.Commit()
	c.JSON(http.StatusOK, gin.H{"message": "Default payment method updated"})
}
