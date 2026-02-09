package config

import (
	"log"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	// Database
	DBHost     string `mapstructure:"DB_HOST"`
	DBPort     string `mapstructure:"DB_PORT"`
	DBUser     string `mapstructure:"DB_USER"`
	DBPassword string `mapstructure:"DB_PASSWORD"`
	DBName     string `mapstructure:"DB_NAME"`

	// Google OAuth
	GoogleClientID     string `mapstructure:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `mapstructure:"GOOGLE_CLIENT_SECRET"`
	GoogleCallbackURL  string `mapstructure:"GOOGLE_CALLBACK_URL"`

	// JWT
	JWTSecret string `mapstructure:"JWT_SECRET"`

	// Centrifugo
	CentrifugoURL         string `mapstructure:"CENTRIFUGO_URL"`          // Internal URL for API calls
	CentrifugoPublicURL   string `mapstructure:"CENTRIFUGO_PUBLIC_URL"`   // Public URL for browser WebSocket
	CentrifugoAPIKey      string `mapstructure:"CENTRIFUGO_API_KEY"`
	CentrifugoTokenSecret string `mapstructure:"CENTRIFUGO_TOKEN_SECRET"`

	// Rage4 DNS (for dynamic proxy routing)
	Rage4Email       string `mapstructure:"RAGE4_EMAIL"`        // Rage4 account email
	Rage4APIKey      string `mapstructure:"RAGE4_API_KEY"`      // Rage4 API key
	Rage4DomainID    int64  `mapstructure:"RAGE4_DOMAIN_ID"`    // Rage4 domain ID
	Rage4DomainName  string `mapstructure:"RAGE4_DOMAIN_NAME"`  // Base domain (e.g., "yalx.in")
	Rage4CNAMEPrefix string `mapstructure:"RAGE4_CNAME_PREFIX"` // CNAME prefix (e.g., "cn" for *.cn.yalx.in)

	// Server
	Port        string `mapstructure:"PORT"`
	Env         string `mapstructure:"ENV"`
	FrontendURL string `mapstructure:"FRONTEND_URL"`
	APIBaseURL  string `mapstructure:"API_BASE_URL"` // Public API URL (e.g., https://api.alobot.io)
}

var AppConfig *Config

func Load() (*Config, error) {
	viper.AutomaticEnv()

	// Explicitly bind environment variables
	viper.BindEnv("DB_HOST")
	viper.BindEnv("DB_PORT")
	viper.BindEnv("DB_USER")
	viper.BindEnv("DB_PASSWORD")
	viper.BindEnv("DB_NAME")
	viper.BindEnv("GOOGLE_CLIENT_ID")
	viper.BindEnv("GOOGLE_CLIENT_SECRET")
	viper.BindEnv("GOOGLE_CALLBACK_URL")
	viper.BindEnv("JWT_SECRET")
	viper.BindEnv("CENTRIFUGO_URL")
	viper.BindEnv("CENTRIFUGO_PUBLIC_URL")
	viper.BindEnv("CENTRIFUGO_API_KEY")
	viper.BindEnv("CENTRIFUGO_TOKEN_SECRET")
	viper.BindEnv("PORT")
	viper.BindEnv("ENV")
	viper.BindEnv("FRONTEND_URL")
	viper.BindEnv("API_BASE_URL")

	// Rage4 DNS
	viper.BindEnv("RAGE4_EMAIL")
	viper.BindEnv("RAGE4_API_KEY")
	viper.BindEnv("RAGE4_DOMAIN_ID")
	viper.BindEnv("RAGE4_DOMAIN_NAME")
	viper.BindEnv("RAGE4_CNAME_PREFIX")

	// Set defaults
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("ENV", "development")
	viper.SetDefault("FRONTEND_URL", "http://localhost:5173")
	viper.SetDefault("CENTRIFUGO_URL", "http://localhost:8000")
	viper.SetDefault("CENTRIFUGO_PUBLIC_URL", "") // Falls back to CENTRIFUGO_URL if not set
	viper.SetDefault("API_BASE_URL", "https://api.alobot.io")
	viper.SetDefault("RAGE4_CNAME_PREFIX", "cn") // Default CNAME prefix

	// Only try to read .env file if it exists
	if _, err := os.Stat(".env"); err == nil {
		viper.SetConfigFile(".env")
		if err := viper.ReadInConfig(); err != nil {
			log.Printf("Warning: Error reading .env file: %v", err)
		} else {
			log.Println("Loaded configuration from .env file")
		}
	} else {
		log.Println("No .env file found, using environment variables")
	}

	// Get Centrifugo public URL, fallback to internal URL if not set
	centrifugoPublicURL := viper.GetString("CENTRIFUGO_PUBLIC_URL")
	if centrifugoPublicURL == "" {
		centrifugoPublicURL = viper.GetString("CENTRIFUGO_URL")
	}

	config := &Config{
		DBHost:                viper.GetString("DB_HOST"),
		DBPort:                viper.GetString("DB_PORT"),
		DBUser:                viper.GetString("DB_USER"),
		DBPassword:            viper.GetString("DB_PASSWORD"),
		DBName:                viper.GetString("DB_NAME"),
		GoogleClientID:        viper.GetString("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:    viper.GetString("GOOGLE_CLIENT_SECRET"),
		GoogleCallbackURL:     viper.GetString("GOOGLE_CALLBACK_URL"),
		JWTSecret:             viper.GetString("JWT_SECRET"),
		CentrifugoURL:         viper.GetString("CENTRIFUGO_URL"),
		CentrifugoPublicURL:   centrifugoPublicURL,
		CentrifugoAPIKey:      viper.GetString("CENTRIFUGO_API_KEY"),
		CentrifugoTokenSecret: viper.GetString("CENTRIFUGO_TOKEN_SECRET"),
		Rage4Email:            viper.GetString("RAGE4_EMAIL"),
		Rage4APIKey:           viper.GetString("RAGE4_API_KEY"),
		Rage4DomainID:         viper.GetInt64("RAGE4_DOMAIN_ID"),
		Rage4DomainName:       viper.GetString("RAGE4_DOMAIN_NAME"),
		Rage4CNAMEPrefix:      viper.GetString("RAGE4_CNAME_PREFIX"),
		Port:                  viper.GetString("PORT"),
		Env:                   viper.GetString("ENV"),
		FrontendURL:           viper.GetString("FRONTEND_URL"),
		APIBaseURL:            viper.GetString("API_BASE_URL"),
	}

	AppConfig = config

	// Log config values at startup (non-sensitive only)
	log.Printf("=== API Configuration ===")
	log.Printf("ENV: %s", config.Env)
	log.Printf("PORT: %s", config.Port)
	log.Printf("API_BASE_URL: %s", config.APIBaseURL)
	log.Printf("FRONTEND_URL: %s", config.FrontendURL)
	log.Printf("DB_HOST: %s", config.DBHost)
	log.Printf("=========================")

	return config, nil
}

func (c *Config) GetDSN() string {
	return "host=" + c.DBHost +
		" user=" + c.DBUser +
		" password=" + c.DBPassword +
		" dbname=" + c.DBName +
		" port=" + c.DBPort +
		" sslmode=disable"
}
