package api

import (
	"context"
	"fmt"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/ids"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// DefenseHandler 防御处理器
type DefenseHandler struct {
	idsInstances map[uint]*ids.IDS // 任务 ID -> IDS 实例
	mu           sync.RWMutex
}

// NewDefenseHandler 创建防御处理器
func NewDefenseHandler() *DefenseHandler {
	return &DefenseHandler{
		idsInstances: make(map[uint]*ids.IDS),
	}
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
		RespondBadRequest(c, err.Error())
		return
	}

	// 验证输入参数
	// 验证敏感度范围（1-10）
	if req.Sensitivity < 1 || req.Sensitivity > 10 {
		RespondBadRequest(c, "Sensitivity must be between 1 and 10")
		return
	}

	// 验证告警阈值（必须大于0）
	if req.AlertThreshold < 1 {
		RespondBadRequest(c, "Alert threshold must be greater than 0")
		return
	}

	// 验证规则数组（不得为空）
	if len(req.Rules) == 0 {
		RespondBadRequest(c, "At least one detection rule must be selected")
		return
	}

	// 验证规则名称（白名单）
	validRules := map[string]bool{
		"port_scan":     true,
		"dos":           true,
		"brute_force":   true,
		"sql_injection": true,
		"xss":           true,
		"malware":       true,
	}

	for _, rule := range req.Rules {
		if !validRules[rule] {
			RespondBadRequest(c, fmt.Sprintf("Invalid rule: %s. Supported rules: port_scan, dos, brute_force, sql_injection, xss, malware", rule))
			return
		}
	}

	// 验证接口名称（复用 capture_handler 的验证函数）
	if !isValidInterface(req.Interface) {
		RespondBadRequest(c, "Invalid interface name. Please use a valid network interface (e.g., eth0, wlan0, any)")
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
		RespondInternalError(c, "Failed to create task")
		return
	}

	logger.GetLogger().Infof("IDS task started: %s on interface %s with rules: %v", taskID, req.Interface, req.Rules)

	// 异步执行 IDS
	go h.runIDS(context.Background(), task, req)

	RespondSuccess(c, gin.H{
		"message": "IDS started",
		"taskId":  task.ID,
		"task":    task,
	})
}

// runIDS 运行真实的 IDS
func (h *DefenseHandler) runIDS(ctx context.Context, task *models.DefenseTask, req StartIDSRequest) {
	// 创建 IDS 实例
	idsInstance := ids.NewIDS(req.Interface, req.Mode, req.Rules, req.Sensitivity, req.AlertThreshold, req.AutoBlock)

	// 保存 IDS 实例
	h.mu.Lock()
	h.idsInstances[task.ID] = idsInstance
	h.mu.Unlock()

	// 启动 IDS
	if err := idsInstance.Start(ctx); err != nil {
		logger.GetLogger().Errorf("Failed to start IDS: %v", err)
		task.Status = "failed"
		task.CompletedAt = timePtr(time.Now())
		database.GetDB().Save(task)

		h.mu.Lock()
		delete(h.idsInstances, task.ID)
		h.mu.Unlock()
		return
	}

	logger.GetLogger().Infof("Real IDS started for task %d on interface %s", task.ID, req.Interface)

	// 定期更新任务状态
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			idsInstance.Stop()
			h.mu.Lock()
			delete(h.idsInstances, task.ID)
			h.mu.Unlock()
			return
		case <-ticker.C:
			// 检查任务是否被停止
			var currentTask models.DefenseTask
			if err := database.GetDB().First(&currentTask, task.ID).Error; err == nil {
				if currentTask.Status != "running" {
					idsInstance.Stop()
					h.mu.Lock()
					delete(h.idsInstances, task.ID)
					h.mu.Unlock()
					return
				}
			}

			// 获取 IDS 统计信息
			stats := idsInstance.GetStatistics()
			recentAlerts := idsInstance.GetRecentAlerts(10)

			// 保存新告警到独立表
			h.saveAlertsToDatabase(task.ID, recentAlerts)

			// 转换告警为 JSON 格式（用于快速显示）
			alertsJSON := make([]interface{}, 0)
			for _, alert := range recentAlerts {
				alertsJSON = append(alertsJSON, map[string]interface{}{
					"type":        alert.Type,
					"severity":    alert.Severity,
					"description": alert.Description,
					"source":      alert.Source,
					"destination": alert.Destination,
					"timestamp":   alert.Timestamp,
					"details":     alert.Details,
				})
			}

			// 查询数据库中的总告警数
			var totalAlerts int64
			database.GetDB().Model(&models.IDSAlert{}).Where("task_id = ?", task.ID).Count(&totalAlerts)

			// 更新任务状态
			task.EventsDetected = int(stats.EventsDetected)
			task.AlertsCount = int(totalAlerts)
			task.BlocksCount = int(stats.BlocksExecuted)
			task.RecentAlerts = models.JSON{"alerts": alertsJSON}

			// 保存到数据库
			database.GetDB().Save(task)
		}
	}
}

// StopIDS 停止 IDS
func (h *DefenseHandler) StopIDS(c *gin.Context) {
	taskID := c.Param("id")

	var task models.DefenseTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	// 停止 IDS 实例
	h.mu.Lock()
	if idsInstance, exists := h.idsInstances[task.ID]; exists {
		idsInstance.Stop()
		delete(h.idsInstances, task.ID)
	}
	h.mu.Unlock()

	task.Status = "stopped"
	task.CompletedAt = timePtr(time.Now())
	database.GetDB().Save(&task)

	logger.GetLogger().Infof("IDS task stopped: %s", task.TaskID)

	RespondSuccess(c, gin.H{"message": "IDS stopped"})
}

// DeleteIDSTask 删除 IDS 任务
func (h *DefenseHandler) DeleteIDSTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.DefenseTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	// 检查任务状态，不能删除正在运行的任务
	if task.Status == "running" {
		RespondBadRequest(c, "Cannot delete running task, please stop it first")
		return
	}

	// 删除任务
	if err := database.GetDB().Delete(&task).Error; err != nil {
		RespondInternalError(c, "Failed to delete task")
		return
	}

	logger.GetLogger().Infof("IDS task deleted: %s", task.TaskID)

	RespondSuccess(c, gin.H{"message": "Task deleted successfully"})
}

// BatchDeleteIDSTasks 批量删除 IDS 任务
func (h *DefenseHandler) BatchDeleteIDSTasks(c *gin.Context) {
	var req struct {
		TaskIDs []uint `json:"task_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	if len(req.TaskIDs) == 0 {
		RespondBadRequest(c, "No task IDs provided")
		return
	}

	// 检查是否有正在运行的任务
	var runningCount int64
	database.GetDB().Model(&models.DefenseTask{}).
		Where("id IN ? AND status = ?", req.TaskIDs, "running").
		Count(&runningCount)

	if runningCount > 0 {
		RespondBadRequest(c, "Cannot delete running tasks, please stop them first")
		return
	}

	// 批量删除
	result := database.GetDB().Where("id IN ?", req.TaskIDs).Delete(&models.DefenseTask{})
	if result.Error != nil {
		RespondInternalError(c, "Failed to delete tasks")
		return
	}

	logger.GetLogger().Infof("Batch deleted %d IDS tasks", result.RowsAffected)

	RespondSuccess(c, gin.H{
		"message": "Tasks deleted successfully",
		"deleted": result.RowsAffected,
	})
}

// GetIDSTasks 获取 IDS 任务列表（支持分页）
func (h *DefenseHandler) GetIDSTasks(c *gin.Context) {
	// 获取分页参数
	params := GetPaginationParams(c)

	// 查询总数
	var total int64
	database.GetDB().Model(&models.DefenseTask{}).Where("type = ?", "ids").Count(&total)

	// 查询任务列表
	var tasks []models.DefenseTask
	database.GetDB().
		Where("type = ?", "ids").
		Order("created_at DESC").
		Offset(params.GetOffset()).
		Limit(params.GetLimit()).
		Find(&tasks)

	// 计算元数据
	meta := CalculateMeta(total, params.Page, params.PageSize)

	// 返回标准响应
	RespondSuccessWithMeta(c, gin.H{"tasks": tasks}, meta)
}

// saveAlertsToDatabase 保存告警到数据库
func (h *DefenseHandler) saveAlertsToDatabase(taskID uint, alerts []ids.Alert) {
	if len(alerts) == 0 {
		return
	}

	db := database.GetDB()

	// 获取已存在的告警时间戳（用于去重）
	var existingTimestamps []time.Time
	db.Model(&models.IDSAlert{}).
		Where("task_id = ?", taskID).
		Order("timestamp DESC").
		Limit(100).
		Pluck("timestamp", &existingTimestamps)

	// 创建时间戳映射用于快速查找
	timestampMap := make(map[int64]bool)
	for _, ts := range existingTimestamps {
		timestampMap[ts.UnixNano()] = true
	}

	// 保存新告警
	for _, alert := range alerts {
		// 检查是否已存在（根据时间戳去重）
		if timestampMap[alert.Timestamp.UnixNano()] {
			continue
		}

		// 创建告警记录
		idsAlert := &models.IDSAlert{
			TaskID:      taskID,
			Type:        alert.Type,
			Severity:    alert.Severity,
			Description: alert.Description,
			Source:      alert.Source,
			Destination: alert.Destination,
			Details:     models.JSON(alert.Details),
			Status:      "new",
			Timestamp:   alert.Timestamp,
			CreatedAt:   time.Now(),
		}

		// 保存到数据库
		if err := db.Create(idsAlert).Error; err != nil {
			logger.GetLogger().Errorf("Failed to save alert to database: %v", err)
		} else {
			// 添加到映射，避免重复保存
			timestampMap[alert.Timestamp.UnixNano()] = true
		}
	}
}

// GetIDSAlerts 获取 IDS 告警列表（支持分页和过滤）
func (h *DefenseHandler) GetIDSAlerts(c *gin.Context) {
	// 获取分页参数
	params := GetPaginationParams(c)

	// 获取过滤参数
	taskID := c.Query("task_id")
	alertType := c.Query("type")
	severity := c.Query("severity")
	status := c.Query("status")
	source := c.Query("source")

	// 构建查询
	query := database.GetDB().Model(&models.IDSAlert{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if alertType != "" {
		query = query.Where("type = ?", alertType)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if source != "" {
		query = query.Where("source = ?", source)
	}

	// 查询总数
	var total int64
	query.Count(&total)

	// 查询告警列表
	var alerts []models.IDSAlert
	query.Order("timestamp DESC").
		Offset(params.GetOffset()).
		Limit(params.GetLimit()).
		Find(&alerts)

	// 计算元数据
	meta := CalculateMeta(total, params.Page, params.PageSize)

	// 返回标准响应
	RespondSuccessWithMeta(c, gin.H{"alerts": alerts}, meta)
}

// GetIDSAlertDetail 获取告警详情
func (h *DefenseHandler) GetIDSAlertDetail(c *gin.Context) {
	alertID := c.Param("id")

	var alert models.IDSAlert
	if err := database.GetDB().First(&alert, alertID).Error; err != nil {
		RespondNotFound(c, "Alert not found")
		return
	}

	RespondSuccess(c, gin.H{"alert": alert})
}

// UpdateIDSAlertStatus 更新告警状态
func (h *DefenseHandler) UpdateIDSAlertStatus(c *gin.Context) {
	alertID := c.Param("id")

	var req struct {
		Status         string `json:"status" binding:"required,oneof=new acknowledged resolved ignored"`
		AcknowledgedBy string `json:"acknowledgedBy"`
		ResolvedBy     string `json:"resolvedBy"`
		Notes          string `json:"notes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	var alert models.IDSAlert
	if err := database.GetDB().First(&alert, alertID).Error; err != nil {
		RespondNotFound(c, "Alert not found")
		return
	}

	// 更新状态
	alert.Status = req.Status
	if req.Notes != "" {
		alert.Notes = req.Notes
	}

	now := time.Now()
	if req.Status == "acknowledged" && req.AcknowledgedBy != "" {
		alert.AcknowledgedBy = req.AcknowledgedBy
		alert.AcknowledgedAt = &now
	}
	if req.Status == "resolved" && req.ResolvedBy != "" {
		alert.ResolvedBy = req.ResolvedBy
		alert.ResolvedAt = &now
	}

	if err := database.GetDB().Save(&alert).Error; err != nil {
		RespondInternalError(c, "Failed to update alert")
		return
	}

	RespondSuccess(c, gin.H{"alert": alert})
}

// DeleteIDSAlert 删除告警
func (h *DefenseHandler) DeleteIDSAlert(c *gin.Context) {
	alertID := c.Param("id")

	// 查找告警
	var alert models.IDSAlert
	if err := database.GetDB().First(&alert, alertID).Error; err != nil {
		RespondNotFound(c, "Alert not found")
		return
	}

	// 删除告警
	if err := database.GetDB().Delete(&alert).Error; err != nil {
		RespondInternalError(c, "Failed to delete alert")
		return
	}

	RespondSuccess(c, gin.H{"message": "Alert deleted successfully"})
}

// BatchDeleteIDSAlerts 批量删除告警
func (h *DefenseHandler) BatchDeleteIDSAlerts(c *gin.Context) {
	var req struct {
		AlertIDs []uint `json:"alert_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	if len(req.AlertIDs) == 0 {
		RespondBadRequest(c, "No alert IDs provided")
		return
	}

	// 批量删除
	result := database.GetDB().Where("id IN ?", req.AlertIDs).Delete(&models.IDSAlert{})
	if result.Error != nil {
		RespondInternalError(c, "Failed to delete alerts")
		return
	}

	RespondSuccess(c, gin.H{
		"message": "Alerts deleted successfully",
		"deleted": result.RowsAffected,
	})
}

// GetIDSAlertsStats 获取告警统计
func (h *DefenseHandler) GetIDSAlertsStats(c *gin.Context) {
	taskID := c.Query("task_id")

	query := database.GetDB().Model(&models.IDSAlert{})
	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	// 总告警数
	var total int64
	query.Count(&total)

	// 按类型统计
	var typeStats []struct {
		Type  string `json:"type"`
		Count int64  `json:"count"`
	}
	database.GetDB().Model(&models.IDSAlert{}).
		Select("type, COUNT(*) as count").
		Group("type").
		Scan(&typeStats)

	// 按严重程度统计
	var severityStats []struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	database.GetDB().Model(&models.IDSAlert{}).
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityStats)

	// 按状态统计
	var statusStats []struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	database.GetDB().Model(&models.IDSAlert{}).
		Select("status, COUNT(*) as count").
		Group("status").
		Scan(&statusStats)

	// 最近 24 小时趋势
	var hourlyStats []struct {
		Hour  string `json:"hour"`
		Count int64  `json:"count"`
	}
	database.GetDB().Model(&models.IDSAlert{}).
		Select("strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count").
		Where("timestamp >= datetime('now', '-24 hours')").
		Group("hour").
		Order("hour ASC").
		Scan(&hourlyStats)

	RespondSuccess(c, gin.H{
		"total":       total,
		"byType":      typeStats,
		"bySeverity":  severityStats,
		"byStatus":    statusStats,
		"hourlyTrend": hourlyStats,
	})
}
