package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/middleware"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
