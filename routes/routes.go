package routes

import (
	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/handlers"
	"github.com/droidproxy/api/middleware"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func Setup(cfg *config.Config) *gin.Engine {
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.FrontendURL, "http://localhost:3000", "http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Phone-ID", "X-Phone-Token", "X-Signature", "X-Timestamp"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Debug config (temporary)
	r.GET("/debug/config", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"api_base_url": cfg.APIBaseURL,
			"db_host":      cfg.DBHost,
			"port":         cfg.Port,
		})
	})

	// Auth routes (no auth required)
	auth := r.Group("/auth")
	{
		auth.POST("/register", handlers.Register)
		auth.POST("/login", handlers.Login)
		auth.GET("/google", handlers.GoogleLogin)
		auth.GET("/google/callback", handlers.GoogleCallback)
	}

	// Phone pairing routes (no auth required - uses pairing code/credentials)
	r.POST("/api/pair", handlers.PairPhone)                        // QR + PIN method
	r.GET("/api/phones/available", handlers.GetUserPhonesForLogin) // Get unpaired phones for login
	r.POST("/api/phone-login", handlers.PhoneLogin)                // Email/password method
	r.POST("/api/heartbeat", handlers.Heartbeat)

	// Public rotation API (uses rotation token, no user auth)
	r.GET("/api/rotate/:token", handlers.RotateIPByToken)
	r.POST("/api/rotate/:token", handlers.RotateIPByToken)

	// Centrifugo proxy endpoint (updates database when phones publish status)
	r.POST("/api/centrifugo/publish", handlers.CentrifugoPublishProxy)


	// Phone-authenticated routes (requires X-Phone-ID and X-Phone-Token headers)
	// These endpoints are exclusively for paired phones
	phoneAPI := r.Group("/api/phone")
	phoneAPI.Use(middleware.PhoneAuthRequired())
	{
		// Read-only endpoints - token auth is sufficient
		phoneAPI.GET("/config", handlers.GetProxyConfig)
		phoneAPI.GET("/credentials", handlers.GetPhoneCredentials)

		// Sensitive write operations - require signature verification
		// This prevents token theft from being used without the private key
		signedPhoneAPI := phoneAPI.Group("")
		signedPhoneAPI.Use(middleware.SignatureRequired())
		{
			signedPhoneAPI.POST("/refresh-token", handlers.RefreshPhoneToken)
		}
	}

	// Protected API routes
	api := r.Group("/api")
	api.Use(middleware.AuthRequired())
	{
		// User info
		api.GET("/me", handlers.GetMe)
		api.POST("/auth/refresh", handlers.RefreshToken)
		api.POST("/auth/logout", handlers.Logout)

		// Phones
		api.GET("/phones", handlers.ListPhones)
		api.POST("/phones", handlers.CreatePhone)
		api.GET("/phones/:id", handlers.GetPhone)
		api.DELETE("/phones/:id", handlers.DeletePhone)
		api.POST("/phones/:id/rotate-ip", handlers.RotateIP)
		api.POST("/phones/:id/restart", handlers.RestartProxy)
		api.POST("/phones/:id/setup-dns", handlers.SetupPhoneDNS)
		api.GET("/phones/:id/stats", handlers.GetPhoneStats)

		// Connection Credentials
		api.GET("/phones/:id/credentials", handlers.ListCredentials)
		api.POST("/phones/:id/credentials", handlers.CreateCredential)
		api.PATCH("/phones/:id/credentials/:credId", handlers.UpdateCredential)
		api.DELETE("/phones/:id/credentials/:credId", handlers.DeleteCredential)

		// Rotation Token
		api.GET("/phones/:id/rotation-token", handlers.GetRotationToken)
		api.POST("/phones/:id/rotation-token/regenerate", handlers.RegenerateRotationToken)

		// Rotation Settings
		api.GET("/phones/:id/rotation-settings", handlers.GetRotationSettings)
		api.PUT("/phones/:id/rotation-settings", handlers.UpdateRotationSettings)

		// Usage & Uptime
		api.GET("/phones/:id/data-usage", handlers.GetPhoneDataUsage)
		api.GET("/phones/:id/uptime", handlers.GetPhoneUptime)
		api.GET("/usage/overview", handlers.GetAllPhonesUsage)

		// Groups
		api.GET("/groups", handlers.ListGroups)
		api.POST("/groups", handlers.CreateGroup)
		api.GET("/groups/:id", handlers.GetGroup)
		api.PUT("/groups/:id", handlers.UpdateGroup)
		api.DELETE("/groups/:id", handlers.DeleteGroup)
		api.POST("/groups/:id/phones", handlers.AddPhonesToGroup)
		api.DELETE("/groups/:id/phones/:phoneId", handlers.RemovePhoneFromGroup)

		// Mass Actions
		api.POST("/phones/actions/mass-rotate", handlers.MassRotateIP)
		api.POST("/phones/actions/mass-rotation-settings", handlers.MassUpdateRotationSettings)
		api.POST("/phones/actions/mass-credentials", handlers.MassCreateCredentials)
		api.POST("/phones/actions/mass-delete", handlers.MassDeletePhones)
		api.POST("/phones/actions/export", handlers.ExportProxies)

		// Servers (read for all, write for admins)
		api.GET("/servers", handlers.ListServers)
		api.GET("/servers/:id", handlers.GetServer)

		// Admin-only routes
		admin := api.Group("")
		admin.Use(middleware.AdminRequired())
		{
			// Server management
			admin.POST("/servers", handlers.CreateServer)
			admin.PUT("/servers/:id", handlers.UpdateServer)
			admin.DELETE("/servers/:id", handlers.DeleteServer)

			// Server SSH management
			admin.POST("/servers/:id/ssh/test", handlers.TestSSHConnection)
			admin.POST("/servers/:id/ssh/exec", handlers.RunSSHCommand)
			admin.POST("/servers/:id/setup", handlers.SetupServer)

			// HTTP Proxy management (gost-based HTTP-to-SOCKS5 converter)
			admin.POST("/servers/:id/http-proxy/start", handlers.StartHTTPProxy)
			admin.DELETE("/servers/:id/http-proxy/:phone_id", handlers.StopHTTPProxy)

			// Firewall management
			admin.GET("/servers/:id/firewall", handlers.GetFirewallStatus)
			admin.POST("/servers/:id/firewall", handlers.ManageFirewall)

			// DNS management
			admin.POST("/servers/:id/dns/setup", handlers.SetupServerDNS)  // Create A record for server
			admin.POST("/servers/:id/failover", handlers.FailoverServer)   // Redirect all phones to another server

			// Hub Agent management
			admin.GET("/servers/:id/telemetry", handlers.GetServerTelemetry) // Get real-time telemetry from hub-agent
			admin.POST("/servers/:id/provision", handlers.ProvisionServer)   // Install hub-agent via SSH

			// User management
			admin.GET("/users", handlers.ListUsers)
			admin.GET("/users/:id", handlers.GetUser)
			admin.PUT("/users/:id/role", handlers.UpdateUserRole)
			admin.DELETE("/users/:id", handlers.DeleteUser)

			// Maintenance
			admin.POST("/cleanup/usage", handlers.CleanupOldUsageData)
		}
	}

	return r
}
