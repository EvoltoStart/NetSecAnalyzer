package database

import (
	"fmt"
	"log"
	"netsecanalyzer/internal/config"
	"netsecanalyzer/internal/models"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB 初始化数据库连接
func InitDB(cfg *config.DatabaseConfig) error {
	var dialector gorm.Dialector
	var err error

	// 根据配置选择数据库驱动
	switch cfg.Type {
	case "sqlite":
		// SQLite 模式
		dbPath := cfg.DBName
		if dbPath == "" {
			dbPath = "./data/netsecanalyzer.db"
		}

		// 确保数据目录存在
		dbDir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}

		dialector = sqlite.Open(dbPath)
		log.Printf("Using SQLite database: %s", dbPath)

	case "mysql", "":
		// MySQL 模式（默认）
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local",
			cfg.User,
			cfg.Password,
			cfg.Host,
			cfg.Port,
			cfg.DBName,
			cfg.Charset,
		)
		dialector = mysql.Open(dsn)
		log.Printf("Using MySQL database: %s@%s:%d/%s", cfg.User, cfg.Host, cfg.Port, cfg.DBName)

	default:
		return fmt.Errorf("unsupported database type: %s (supported: mysql, sqlite)", cfg.Type)
	}

	// 打开数据库连接
	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Warn), // 只打印警告和错误，不打印所有 SQL
		DisableForeignKeyConstraintWhenMigrating: true,                                // 禁用外键约束管理
		SkipDefaultTransaction:                   true,                                // 跳过默认事务，提升性能
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// 配置连接池
	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// 设置连接池参数（SQLite 建议较小的值）
	maxIdleConns := cfg.MaxIdleConns
	maxOpenConns := cfg.MaxOpenConns
	if cfg.Type == "sqlite" {
		// SQLite 不支持高并发，限制连接数
		if maxIdleConns > 5 {
			maxIdleConns = 5
		}
		if maxOpenConns > 10 {
			maxOpenConns = 10
		}
	}

	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// 自动迁移数据库表
	if err := autoMigrateSafely(); err != nil {
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

// autoMigrateSafely 安全地自动迁移所有表
// 使用 Migrator 的 CreateTable 方法来避免 GORM 的外键约束 bug
func autoMigrateSafely() error {
	models := []interface{}{
		&models.CaptureSession{},
		&models.Packet{},
		&models.Vulnerability{},
		&models.ScanTask{},
		&models.ScanResult{},
		&models.AttackLog{},
		&models.AttackTask{},
		&models.DefenseTask{},
		&models.IDSAlert{},
		&models.ProtocolStat{},
	}

	migrator := DB.Migrator()

	for _, model := range models {
		tableName := DB.NamingStrategy.TableName(reflect.TypeOf(model).Elem().Name())

		if !migrator.HasTable(model) {
			// 表不存在，使用 CreateTable 创建
			log.Printf("Creating table: %s", tableName)
			if err := migrator.CreateTable(model); err != nil {
				return fmt.Errorf("failed to create table %s: %w", tableName, err)
			}
		} else {
			// 表已存在，跳过迁移（避免 GORM 的索引处理 bug）
			log.Printf("Table %s already exists, skipping migration", tableName)
			// 如果将来需要添加新列，可以使用 migrator.AddColumn()
		}
	}

	return nil
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
