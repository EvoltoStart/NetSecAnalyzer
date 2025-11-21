package api

import (
	"netsecanalyzer/internal/analyzer"
	"netsecanalyzer/internal/attack"
	"netsecanalyzer/internal/middleware"
	"netsecanalyzer/internal/scanner"
	"time"

	"github.com/gin-gonic/gin"
)

// Router API 路由器
type Router struct {
	engine          *gin.Engine
	captureHandler  *CaptureHandler
	analyzeHandler  *AnalyzeHandler
	scanHandler     *ScanHandler
	attackHandler   *AttackHandler
	defenseHandler  *DefenseHandler
	statsHandler    *StatsHandler
	idsRulesHandler *IDSRulesHandler
}

// NewRouter 创建路由器
func NewRouter(mode string) *Router {
	gin.SetMode(mode)
	engine := gin.New()

	// 中间件
	engine.Use(gin.Recovery())
	engine.Use(middleware.Logger())
	engine.Use(middleware.CORS())

	// 创建处理器
	captureHandler := NewCaptureHandler()
	analyzeHandler := NewAnalyzeHandler(analyzer.NewAnalyzer())
	scanHandler := NewScanHandler(scanner.NewScanner(100, 5*time.Second, 1000))
	attackHandler := NewAttackHandler(attack.NewAttackManager(true, 100))
	defenseHandler := NewDefenseHandler()
	statsHandler := NewStatsHandler()
	idsRulesHandler := NewIDSRulesHandler()

	router := &Router{
		engine:          engine,
		captureHandler:  captureHandler,
		analyzeHandler:  analyzeHandler,
		scanHandler:     scanHandler,
		attackHandler:   attackHandler,
		defenseHandler:  defenseHandler,
		statsHandler:    statsHandler,
		idsRulesHandler: idsRulesHandler,
	}

	router.setupRoutes()
	return router
}

// setupRoutes 设置路由
func (r *Router) setupRoutes() {
	api := r.engine.Group("/api")
	{
		// 健康检查
		api.GET("/health", r.healthCheck)

		// 数据采集
		capture := api.Group("/capture")
		{
			capture.POST("/start", r.captureHandler.StartCapture)
			capture.POST("/stop", r.captureHandler.StopCapture)
			capture.GET("/sessions", r.captureHandler.ListSessions)
			capture.GET("/sessions/:id", r.captureHandler.GetSession)
			capture.GET("/sessions/:id/packets", r.captureHandler.GetPackets)
			capture.DELETE("/sessions/:id", r.captureHandler.DeleteSession)
			capture.GET("/interfaces", r.captureHandler.GetInterfaces)
			capture.GET("/serial-ports", r.captureHandler.GetSerialPorts)
			capture.POST("/upload", r.captureHandler.UploadPCAP)
			capture.GET("/packets/:id/payload", r.captureHandler.GetPayload)
		}

		// WebSocket
		api.GET("/ws", r.captureHandler.HandleWebSocket)

		// 协议分析
		analyze := api.Group("/analyze")
		{
			analyze.POST("/parse", r.analyzeHandler.ParsePacket)
			analyze.GET("/protocols", r.analyzeHandler.GetProtocols)
			analyze.POST("/statistics", r.analyzeHandler.GetStatistics)
			analyze.GET("/packets/:id/result", r.analyzeHandler.GetPacketAnalysis)
			analyze.GET("/sessions/:id/results", r.analyzeHandler.GetSessionAnalysis)
			analyze.GET("/sessions/:id/anomalies", r.analyzeHandler.GetSessionAnomalies)
			analyze.POST("/sessions/:id/reanalyze", r.analyzeHandler.ReanalyzeSession)
		}

		// 漏洞扫描
		scan := api.Group("/scan")
		{
			scan.POST("/start", r.scanHandler.StartScan)
			scan.GET("/tasks", r.scanHandler.ListTasks)
			scan.GET("/tasks/:id", r.scanHandler.GetTask)
			scan.GET("/tasks/:id/results", r.scanHandler.GetTaskResults)
			scan.GET("/tasks/:id/vulnerabilities", r.scanHandler.GetTaskVulnerabilities)
			scan.POST("/tasks/:id/stop", r.scanHandler.StopTask)
			scan.DELETE("/tasks/:id", r.scanHandler.DeleteTask)
		}

		// 攻防模拟
		attack := api.Group("/attack")
		{
			attack.POST("/replay", r.attackHandler.ReplayPackets)
			attack.POST("/fuzz", r.attackHandler.StartFuzzing)
			attack.GET("/tasks", r.attackHandler.GetTasks)
			attack.GET("/tasks/:id", r.attackHandler.GetTask)
			attack.POST("/tasks/:id/stop", r.attackHandler.StopTask)
			attack.DELETE("/tasks/:id", r.attackHandler.DeleteTask)
			attack.POST("/tasks/batch-delete", r.attackHandler.BatchDeleteTasks)
		}

		// 防御模拟
		defense := api.Group("/defense")
		{
			defense.POST("/ids/start", r.defenseHandler.StartIDS)
			defense.POST("/ids/:id/stop", r.defenseHandler.StopIDS)
			defense.DELETE("/ids/tasks/:id", r.defenseHandler.DeleteIDSTask)
			defense.POST("/ids/tasks/batch-delete", r.defenseHandler.BatchDeleteIDSTasks)
			defense.GET("/ids/tasks", r.defenseHandler.GetIDSTasks)

			// 告警管理
			defense.GET("/ids/alerts", r.defenseHandler.GetIDSAlerts)
			defense.GET("/ids/alerts/:id", r.defenseHandler.GetIDSAlertDetail)
			defense.PUT("/ids/alerts/:id", r.defenseHandler.UpdateIDSAlertStatus)
			defense.DELETE("/ids/alerts/:id", r.defenseHandler.DeleteIDSAlert)
			defense.POST("/ids/alerts/batch-delete", r.defenseHandler.BatchDeleteIDSAlerts)
			defense.GET("/ids/alerts/stats", r.defenseHandler.GetIDSAlertsStats)

			// IDS规则管理
			defense.POST("/ids/rules", r.idsRulesHandler.CreateIDSRule)
			defense.GET("/ids/rules", r.idsRulesHandler.GetIDSRules)
			defense.GET("/ids/rules/:id", r.idsRulesHandler.GetIDSRule)
			defense.PUT("/ids/rules/:id", r.idsRulesHandler.UpdateIDSRule)
			defense.DELETE("/ids/rules/:id", r.idsRulesHandler.DeleteIDSRule)
			defense.POST("/ids/rules/:id/toggle", r.idsRulesHandler.ToggleIDSRule)
			defense.GET("/ids/rules/types", r.idsRulesHandler.GetIDSRuleTypes)
			defense.GET("/ids/rules/stats", r.idsRulesHandler.GetIDSRuleStats)
			defense.PUT("/ids/rules/batch", r.idsRulesHandler.BatchUpdateIDSRules)
			defense.GET("/ids/rules/export", r.idsRulesHandler.ExportIDSRules)
			defense.POST("/ids/rules/import", r.idsRulesHandler.ImportIDSRules)
		}

		// 统计数据
		stats := api.Group("/stats")
		{
			stats.GET("/overview", r.statsHandler.GetOverviewStats)
			stats.GET("/protocol-distribution", r.statsHandler.GetProtocolDistribution)
			stats.GET("/traffic-trend", r.statsHandler.GetTrafficTrend)
			stats.GET("/sessions/recent", r.statsHandler.GetRecentSessions)
			stats.GET("/vulnerabilities/recent", r.statsHandler.GetRecentVulnerabilities)
			stats.GET("/sessions/:id/protocols", r.statsHandler.GetSessionProtocolStats)
		}
	}

	// WebSocket 端点
	ws := r.engine.Group("/ws")
	{
		ws.GET("/capture", r.captureHandler.HandleWebSocket)
	}
}

// healthCheck 健康检查
func (r *Router) healthCheck(c *gin.Context) {
	RespondSuccess(c, gin.H{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// Run 运行服务器
func (r *Router) Run(addr string) error {
	return r.engine.Run(addr)
}

// GetEngine 获取 Gin 引擎（用于优雅关机）
func (r *Router) GetEngine() *gin.Engine {
	return r.engine
}
