package database

import (
	"log"

	"github.com/droidproxy/api/config"
	"github.com/droidproxy/api/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Connect(cfg *config.Config) error {
	var err error

	logLevel := logger.Silent
	if cfg.Env == "development" {
		logLevel = logger.Info
	}

	DB, err = gorm.Open(postgres.Open(cfg.GetDSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return err
	}

	log.Println("Database connected successfully")
	return nil
}

func Migrate() error {
	log.Println("Running database migrations...")

	err := DB.AutoMigrate(
		&models.User{},
		&models.HubServer{},
		&models.Phone{},
		&models.PhoneStats{},
		&models.ConnectionCredential{},
		&models.RotationToken{},
		&models.PhoneGroup{},
		&models.PhoneGroupMembership{},
		&models.PhoneDataUsage{},
		&models.PhoneUptimeLog{},
		&models.PhoneDailyUptime{},
		&models.DomainBlocklist{},
	)
	if err != nil {
		return err
	}

	log.Println("Database migrations completed")
	return nil
}

func Close() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
