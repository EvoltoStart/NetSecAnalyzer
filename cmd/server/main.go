package main

import (
	"flag"
	"fmt"
	"log"
	"netsecanalyzer/internal/api"
	"netsecanalyzer/internal/config"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/pkg/logger"
	"os"
	"os/signal"
	"syscall"
)

var (
	configFile = flag.String("config", "./configs/config.yaml", "配置文件路径")
	version    = flag.Bool("version", false, "显示版本信息")
)

const (
	Version = "1.0.0"
	AppName = "NetSecAnalyzer"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%s v%s\n", AppName, Version)
		fmt.Println("网络安全分析系统")
		return
	}

	// 加载配置
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化日志
	if err := logger.InitLogger(
		cfg.Log.Level,
		cfg.Log.Format,
		cfg.Log.Output,
		cfg.Log.FilePath,
		cfg.Log.MaxSize,
		cfg.Log.MaxBackups,
		cfg.Log.MaxAge,
	); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger.GetLogger().Infof("Starting %s v%s", AppName, Version)

	// 初始化数据库
	if err := database.InitDB(&cfg.Database); err != nil {
		logger.GetLogger().Fatalf("Failed to initialize database: %v", err)
	}
	logger.GetLogger().Info("Database initialized successfully")

	// 创建 API 路由器
	router := api.NewRouter(cfg.Server.Mode)
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	logger.GetLogger().Infof("Server starting on %s", addr)

	// 优雅关闭
	go func() {
		if err := router.Run(addr); err != nil {
			logger.GetLogger().Fatalf("Failed to start server: %v", err)
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.GetLogger().Info("Shutting down server...")

	// 关闭数据库连接
	if err := database.CloseDB(); err != nil {
		logger.GetLogger().Errorf("Error closing database: %v", err)
	}

	logger.GetLogger().Info("Server stopped")
}
