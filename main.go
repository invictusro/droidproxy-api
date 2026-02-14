package main

import (
	"log"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/database"
	"github.com/droidproxy/api/handlers"
	"github.com/droidproxy/api/internal/allocator"
	"github.com/droidproxy/api/internal/dns"
	"github.com/droidproxy/api/internal/phone"
	"github.com/droidproxy/api/jobs"
	"github.com/droidproxy/api/routes"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Println("Configuration loaded")

	// Connect to database
	if err := database.Connect(cfg); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Run migrations
	if err := database.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize global IP/port allocator
	if err := allocator.InitializeSettings(); err != nil {
		log.Fatalf("Failed to initialize allocator: %v", err)
	}
	log.Println("Global allocator initialized")

	// Initialize OAuth
	handlers.InitOAuth(cfg)
	log.Println("OAuth initialized")

	// Initialize phone communication services
	phone.InitCommander(cfg.CentrifugoURL, cfg.CentrifugoAPIKey)
	phone.InitRealtime(cfg.CentrifugoURL, cfg.CentrifugoAPIKey, cfg.CentrifugoTokenSecret)

	// Initialize DNS manager for dynamic proxy routing (optional)
	if cfg.Rage4APIKey != "" && cfg.Rage4DomainID != 0 {
		dnsManager := dns.InitGlobal(dns.ManagerConfig{
			Email:       cfg.Rage4Email,
			APIKey:      cfg.Rage4APIKey,
			DomainID:    cfg.Rage4DomainID,
			DomainName:  cfg.Rage4DomainName,
			CNAMEPrefix: cfg.Rage4CNAMEPrefix,
		})
		if err := dnsManager.VerifyConfiguration(); err != nil {
			log.Printf("Warning: DNS manager verification failed: %v", err)
		} else {
			log.Println("DNS manager initialized and verified")
		}
	} else {
		log.Println("DNS manager not configured (RAGE4_API_KEY or RAGE4_DOMAIN_ID missing)")
	}

	// Start background jobs
	jobs.StartLicenseExpiryJob()

	// Setup routes
	router := routes.Setup(cfg)

	// Start server
	log.Printf("Starting server on port %s", cfg.Port)
	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
