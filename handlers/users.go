package handlers

import (
	"net/http"

	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// UpdateRoleRequest is the request body for updating a user's role
type UpdateRoleRequest struct {
	Role string `json:"role" binding:"required,oneof=user admin"`
}

// ListUsers returns all users (admin only)
func ListUsers(c *gin.Context) {
	var users []models.User
	if err := database.DB.Preload("Phones").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	type UserWithStats struct {
		models.UserResponse
		PhoneCount int `json:"phone_count"`
	}

	responses := make([]UserWithStats, len(users))
	for i, user := range users {
		responses[i] = UserWithStats{
			UserResponse: user.ToResponse(),
			PhoneCount:   len(user.Phones),
		}
	}

	c.JSON(http.StatusOK, gin.H{"users": responses})
}

// GetUser returns a specific user (admin only)
func GetUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var user models.User
	if err := database.DB.Preload("Phones").First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user.ToResponse()})
}

// UpdateUserRole changes a user's role (admin only)
func UpdateUserRole(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.Role = models.UserRole(req.Role)
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user.ToResponse()})
}

// DeleteUser removes a user and their phones (admin only)
func DeleteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Delete associated phones first (CASCADE should handle this, but being explicit)
	database.DB.Where("user_id = ?", userID).Delete(&models.Phone{})

	result := database.DB.Delete(&models.User{}, "id = ?", userID)
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}
