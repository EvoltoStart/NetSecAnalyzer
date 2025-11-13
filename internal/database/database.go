package database

import (
	"fmt"
	"log"
	"netsecanalyzer/internal/config"
	"netsecanalyzer/internal/models"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB 初始化数据库连接
func InitDB(cfg *config.DatabaseConfig) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.DBName,
		cfg.Charset,
	)

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn), // 只打印警告和错误，不打印所有 SQL
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// 自动迁移数据库表
	if err := autoMigrate(); err != nil {
		return fmt.Errorf("failed to auto migrate: %w", err)
	}

	// 清理遗留的运行中会话（服务器重启后，之前运行的会话应该标记为停止）
	if err := cleanupRunningSessions(); err != nil {
		log.Printf("Warning: failed to cleanup running sessions: %v", err)
	}

	log.Println("Database connected successfully")
	return nil
}

// autoMigrate 自动迁移所有表
func autoMigrate() error {
	return DB.AutoMigrate(
		&models.CaptureSession{},
		&models.Packet{},
		&models.Vulnerability{},
		&models.ScanTask{},
		&models.ScanResult{},
		&models.AttackLog{},
		&models.AttackTask{},
		&models.DefenseTask{},
		&models.ProtocolStat{},
	)
}

// GetDB 获取数据库实例
func GetDB() *gorm.DB {
	return DB
}

// CloseDB 关闭数据库连接
func CloseDB() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// cleanupRunningSessions 清理遗留的运行中会话
// 服务器重启后，之前状态为 running 的会话应该标记为 stopped
func cleanupRunningSessions() error {
	result := DB.Model(&models.CaptureSession{}).
		Where("status = ?", "running").
		Update("status", "stopped")

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected > 0 {
		log.Printf("Cleaned up %d running sessions on startup", result.RowsAffected)
	}

	return nil
}
