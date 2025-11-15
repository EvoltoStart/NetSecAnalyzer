package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"netsecanalyzer/internal/api"
	"netsecanalyzer/internal/config"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/tasks"
	"netsecanalyzer/pkg/logger"
	"netsecanalyzer/pkg/storage"
	"os"
	"os/signal"
	"syscall"
	"time"
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

	// 初始化 Payload 存储
	payloadStorage, err := storage.NewPayloadStorage("./data/payloads", 100*1024*1024, 30)
	if err != nil {
		logger.GetLogger().Errorf("Failed to create payload storage: %v", err)
	} else {
		logger.GetLogger().Info("Payload storage initialized successfully")
	}

	// 启动清理任务
	var cleanupTask *tasks.CleanupTask
	if payloadStorage != nil {
		cleanupTask = tasks.NewCleanupTask(payloadStorage, 30) // 30天保留期
		cleanupTask.Start()
		logger.GetLogger().Info("Cleanup task started (30 days retention)")
	}

	// 创建 API 路由器
	router := api.NewRouter(cfg.Server.Mode)
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	// 创建 HTTP 服务器以支持优雅关机
	srv := &http.Server{
		Addr:           addr,
		Handler:        router.GetEngine(),
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	logger.GetLogger().Infof("Server starting on %s", addr)

	// 在 goroutine 中启动服务器
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.GetLogger().Fatalf("Failed to start server: %v", err)
		}
	}()

	// 等待中断信号（SIGINT 或 SIGTERM）
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	logger.GetLogger().Infof("Received signal: %v. Shutting down server...", sig)

	// 创建带超时的 context（30 秒）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 优雅关闭服务器（等待现有连接完成）
	if err := srv.Shutdown(ctx); err != nil {
		logger.GetLogger().Errorf("Server forced to shutdown: %v", err)
	} else {
		logger.GetLogger().Info("Server shutdown gracefully")
	}

	// 停止清理任务
	if cleanupTask != nil {
		cleanupTask.Stop()
		logger.GetLogger().Info("Cleanup task stopped")
	}

	// 关闭数据库连接
	logger.GetLogger().Info("Closing database connections...")
	if err := database.CloseDB(); err != nil {
		logger.GetLogger().Errorf("Error closing database: %v", err)
	} else {
		logger.GetLogger().Info("Database connections closed")
	}

	logger.GetLogger().Info("Server stopped successfully")
}
