package api

import (
	"context"
	"fmt"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"time"

	"github.com/gin-gonic/gin"
)

// DefenseHandler 防御处理器
type DefenseHandler struct{}

// NewDefenseHandler 创建防御处理器
func NewDefenseHandler() *DefenseHandler {
	return &DefenseHandler{}
}

// StartIDSRequest IDS 启动请求
type StartIDSRequest struct {
	Interface      string   `json:"interface" binding:"required"`
	Mode           string   `json:"mode" binding:"required,oneof=signature anomaly hybrid"`
	Rules          []string `json:"rules"`
	Sensitivity    int      `json:"sensitivity"`
	AlertThreshold int      `json:"alert_threshold"`
	AutoBlock      bool     `json:"auto_block"`
	UserID         string   `json:"user_id"`
}

// StartIDS 启动入侵检测
func (h *DefenseHandler) StartIDS(c *gin.Context) {
	var req StartIDSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 创建任务记录
	taskID := fmt.Sprintf("ids-%d", time.Now().Unix())
	task := &models.DefenseTask{
		TaskID:    taskID,
		Type:      "ids",
		Interface: req.Interface,
		Status:    "running",
		Parameters: models.JSON(map[string]interface{}{
			"mode":            req.Mode,
			"rules":           req.Rules,
			"sensitivity":     req.Sensitivity,
			"alert_threshold": req.AlertThreshold,
			"auto_block":      req.AutoBlock,
		}),
		EventsDetected: 0,
		AlertsCount:    0,
		BlocksCount:    0,
		UserID:         req.UserID,
		CreatedAt:      time.Now(),
	}

	if err := database.GetDB().Create(task).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create task"})
		return
	}

	logger.GetLogger().Infof("IDS task started: %s on interface %s", taskID, req.Interface)

	// 异步执行 IDS
	go h.runIDS(context.Background(), task, req)

	c.JSON(200, gin.H{
		"message": "IDS started",
		"data":    task,
	})
}

// runIDS 运行 IDS
func (h *DefenseHandler) runIDS(ctx context.Context, task *models.DefenseTask, req StartIDSRequest) {
	// 模拟 IDS 运行
	// 实际实现应该使用 libpcap 捕获流量并分析

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 模拟检测事件
			task.EventsDetected += 10

			// 随机生成告警
			if task.EventsDetected%30 == 0 {
				task.AlertsCount++

				// 添加告警到 recent_alerts
				alert := map[string]interface{}{
					"type":        "port_scan",
					"severity":    "medium",
					"description": "Detected port scanning activity",
					"source":      "192.168.1.100",
					"timestamp":   time.Now(),
				}

				// 构建告警列表
				var alerts []interface{}
				if task.RecentAlerts != nil {
					// 尝试从 JSON 中提取数组
					if alertsData, ok := task.RecentAlerts["alerts"]; ok {
						if alertsArray, ok := alertsData.([]interface{}); ok {
							alerts = alertsArray
						}
					}
				}

				alerts = append([]interface{}{alert}, alerts...)
				if len(alerts) > 10 {
					alerts = alerts[:10]
				}
				task.RecentAlerts = models.JSON{"alerts": alerts}

				// 如果启用自动阻断
				if req.AutoBlock {
					task.BlocksCount++
				}
			}

			// 更新数据库
			database.GetDB().Save(task)

			// 检查任务是否被停止
			var currentTask models.DefenseTask
			if err := database.GetDB().First(&currentTask, task.ID).Error; err == nil {
				if currentTask.Status != "running" {
					return
				}
			}
		}
	}
}

// StopIDS 停止 IDS
func (h *DefenseHandler) StopIDS(c *gin.Context) {
	taskID := c.Param("id")

	var task models.DefenseTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Task not found"})
		return
	}

	task.Status = "stopped"
	task.CompletedAt = timePtr(time.Now())
	database.GetDB().Save(&task)

	logger.GetLogger().Infof("IDS task stopped: %s", task.TaskID)

	c.JSON(200, gin.H{"message": "IDS stopped"})
}

// GetIDSTasks 获取 IDS 任务列表
func (h *DefenseHandler) GetIDSTasks(c *gin.Context) {
	var tasks []models.DefenseTask
	database.GetDB().Where("type = ?", "ids").Order("created_at DESC").Find(&tasks)

	c.JSON(200, gin.H{"data": tasks})
}

func timePtr(t time.Time) *time.Time {
	return &t
}
