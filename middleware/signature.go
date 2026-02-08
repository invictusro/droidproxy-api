package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/droidproxy/api/services"
	"github.com/gin-gonic/gin"
)

const (
	// Maximum age of a signed request (prevents replay attacks)
	maxRequestAge = 5 * time.Minute

	// Header names for signature verification
	SignatureHeader   = "X-Signature"
	TimestampHeader   = "X-Timestamp"
	SignedDataHeader  = "X-Signed-Data" // Optional: explicit signed data for debugging
)

// SignatureRequired middleware verifies ECDSA signatures on requests
// This should be used AFTER PhoneAuthRequired middleware
// The phone must sign: METHOD|PATH|TIMESTAMP|BODY_HASH
func SignatureRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the authenticated phone (set by PhoneAuthRequired)
		phone := GetCurrentPhone(c)
		if phone == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Phone authentication required"})
			c.Abort()
			return
		}

		// Check if phone has a public key (required for signature verification)
		if phone.PublicKey == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Phone not configured for signed requests"})
			c.Abort()
			return
		}

		// Get signature from header
		signature := c.GetHeader(SignatureHeader)
		if signature == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing request signature"})
			c.Abort()
			return
		}

		// Get timestamp from header
		timestampStr := c.GetHeader(TimestampHeader)
		if timestampStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing request timestamp"})
			c.Abort()
			return
		}

		// Parse and validate timestamp
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid timestamp format"})
			c.Abort()
			return
		}

		requestTime := time.Unix(timestamp, 0)
		age := time.Since(requestTime)

		// Check if request is too old (replay attack prevention)
		if age > maxRequestAge {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Request expired"})
			c.Abort()
			return
		}

		// Check if request is from the future (clock skew tolerance: 1 minute)
		if age < -time.Minute {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid timestamp (future)"})
			c.Abort()
			return
		}

		// Read request body (we need to restore it after reading)
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Compute body hash
		bodyHash := sha256.Sum256(bodyBytes)
		bodyHashB64 := base64.StdEncoding.EncodeToString(bodyHash[:])

		// Construct the signed data: METHOD|PATH|TIMESTAMP|BODY_HASH
		signedData := fmt.Sprintf("%s|%s|%s|%s",
			c.Request.Method,
			c.Request.URL.Path,
			timestampStr,
			bodyHashB64,
		)

		// Verify signature
		valid, err := services.VerifySignature(phone.PublicKey, signedData, signature)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify signature"})
			c.Abort()
			return
		}

		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			c.Abort()
			return
		}

		// Signature valid, continue
		c.Set("signatureVerified", true)
		c.Next()
	}
}

// OptionalSignature middleware verifies signatures if present, but doesn't require them
// Useful for transitional periods or endpoints that support both signed and unsigned requests
func OptionalSignature() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the authenticated phone (set by PhoneAuthRequired)
		phone := GetCurrentPhone(c)
		if phone == nil {
			c.Next()
			return
		}

		// Check if signature is provided
		signature := c.GetHeader(SignatureHeader)
		if signature == "" {
			// No signature provided, continue without verification
			c.Set("signatureVerified", false)
			c.Next()
			return
		}

		// If signature is provided, verify it
		timestampStr := c.GetHeader(TimestampHeader)
		if timestampStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Signature provided without timestamp"})
			c.Abort()
			return
		}

		// Parse timestamp
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid timestamp format"})
			c.Abort()
			return
		}

		requestTime := time.Unix(timestamp, 0)
		age := time.Since(requestTime)

		if age > maxRequestAge || age < -time.Minute {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Request timestamp out of range"})
			c.Abort()
			return
		}

		// Read and restore body
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		bodyHash := sha256.Sum256(bodyBytes)
		bodyHashB64 := base64.StdEncoding.EncodeToString(bodyHash[:])

		signedData := fmt.Sprintf("%s|%s|%s|%s",
			c.Request.Method,
			c.Request.URL.Path,
			timestampStr,
			bodyHashB64,
		)

		// Phone must have public key to verify
		if phone.PublicKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Phone not configured for signed requests"})
			c.Abort()
			return
		}

		valid, err := services.VerifySignature(phone.PublicKey, signedData, signature)
		if err != nil || !valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			c.Abort()
			return
		}

		c.Set("signatureVerified", true)
		c.Next()
	}
}

// IsSignatureVerified checks if the current request has a verified signature
func IsSignatureVerified(c *gin.Context) bool {
	verified, exists := c.Get("signatureVerified")
	if !exists {
		return false
	}
	return verified.(bool)
}
