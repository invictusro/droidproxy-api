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
	CentrifugoURL         string `mapstructure:"CENTRIFUGO_URL"`
	CentrifugoAPIKey      string `mapstructure:"CENTRIFUGO_API_KEY"`
	CentrifugoTokenSecret string `mapstructure:"CENTRIFUGO_TOKEN_SECRET"`

	// Server
	Port        string `mapstructure:"PORT"`
	Env         string `mapstructure:"ENV"`
	FrontendURL string `mapstructure:"FRONTEND_URL"`
	APIBaseURL  string `mapstructure:"API_BASE_URL"` // Public API URL (e.g., https://api.alobot.io)
}

var AppConfig *Config

func Load() (*Config, error) {
	viper.AutomaticEnv()

	// Set defaults
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("ENV", "development")
	viper.SetDefault("FRONTEND_URL", "http://localhost:5173")
	viper.SetDefault("CENTRIFUGO_URL", "http://localhost:8000")
	viper.SetDefault("API_BASE_URL", "http://localhost:8080")

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

	config := &Config{}
	if err := viper.Unmarshal(config); err != nil {
		return nil, err
	}

	AppConfig = config
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
