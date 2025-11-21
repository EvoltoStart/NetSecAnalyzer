package api

import (
	"context"
	"fmt"
	"netsecanalyzer/internal/attack"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"time"

	"github.com/gin-gonic/gin"
)

// AttackHandler 攻击处理器
type AttackHandler struct {
	manager  *attack.AttackManager
	replayer *attack.Replayer
	fuzzer   *attack.Fuzzer
}

// NewAttackHandler 创建攻击处理器
func NewAttackHandler(m *attack.AttackManager) *AttackHandler {
	return &AttackHandler{
		manager:  m,
		replayer: attack.NewReplayer(m),
		fuzzer:   attack.NewFuzzer(m),
	}
}

// ReplayPackets 重放数据包
func (h *AttackHandler) ReplayPackets(c *gin.Context) {
	var req struct {
		SessionID         uint    `json:"session_id" binding:"required"`
		Interface         string  `json:"interface" binding:"required"`
		SpeedMultiplier   float64 `json:"speed_multiplier"`
		Mode              string  `json:"mode"`
		LoopCount         int     `json:"loop_count"`
		Duration          int     `json:"duration"`           // 持续时间（秒）
		ProtocolFilter    string  `json:"protocol_filter"`    // 协议过滤
		SrcAddrFilter     string  `json:"src_addr_filter"`    // 源地址过滤
		DstAddrFilter     string  `json:"dst_addr_filter"`    // 目标地址过滤
		PreserveTimestamp bool    `json:"preserve_timestamp"` // 保留时间戳
		ModifyChecksum    bool    `json:"modify_checksum"`    // 修正校验和
		UserID            string  `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	// 设置默认值
	if req.SpeedMultiplier == 0 {
		req.SpeedMultiplier = 1.0
	}
	if req.Mode == "" {
		req.Mode = "once"
	}
	if req.LoopCount == 0 {
		req.LoopCount = 1
	}

	// 检查授权
	if err := h.manager.CheckAuthorization("replay", req.UserID); err != nil {
		RespondError(c, 403, "Unauthorized")
		return
	}

	// 获取会话信息
	var session models.CaptureSession
	if err := database.GetDB().First(&session, req.SessionID).Error; err != nil {
		RespondNotFound(c, "Session not found")
		return
	}

	// 构建数据包查询，支持过滤
	query := database.GetDB().Where("session_id = ?", req.SessionID)

	// 应用过滤器
	if req.ProtocolFilter != "" {
		query = query.Where("protocol = ?", req.ProtocolFilter)
	}
	if req.SrcAddrFilter != "" {
		query = query.Where("src_addr = ?", req.SrcAddrFilter)
	}
	if req.DstAddrFilter != "" {
		query = query.Where("dst_addr = ?", req.DstAddrFilter)
	}

	// 获取过滤后的数据包
	var packets []models.Packet
	query.Find(&packets)

	if len(packets) == 0 {
		RespondNotFound(c, "No packets found")
		return
	}

	// 检查数据包是否有 RawData（用于重放）
	var hasRawDataCount int64
	database.GetDB().Model(&models.Packet{}).
		Where("session_id = ? AND raw_data IS NOT NULL AND length(raw_data) > 0", req.SessionID).
		Count(&hasRawDataCount)

	if hasRawDataCount == 0 {
		RespondError(c, 400, "This session was captured before the replay feature was added. Please recapture the traffic to enable replay.")
		return
	}

	if hasRawDataCount < int64(len(packets)) {
		logger.GetLogger().Warnf("Session %d: only %d/%d packets have RawData", req.SessionID, hasRawDataCount, len(packets))
	}

	// 创建任务记录
	taskID := generateTaskID()
	task := &models.AttackTask{
		TaskID:   taskID,
		Type:     "replay",
		Target:   req.Interface,
		Status:   "running",
		Progress: 0,
		Parameters: models.JSON(map[string]interface{}{
			"session_id":         req.SessionID,
			"session_name":       session.Name,
			"interface":          req.Interface,
			"speed_multiplier":   req.SpeedMultiplier,
			"mode":               req.Mode,
			"loop_count":         req.LoopCount,
			"duration":           req.Duration,
			"protocol_filter":    req.ProtocolFilter,
			"src_addr_filter":    req.SrcAddrFilter,
			"dst_addr_filter":    req.DstAddrFilter,
			"preserve_timestamp": req.PreserveTimestamp,
			"modify_checksum":    req.ModifyChecksum,
			"packet_count":       len(packets),
		}),
		UserID:    req.UserID,
		CreatedAt: time.Now(),
	}

	if err := database.GetDB().Create(task).Error; err != nil {
		logger.GetLogger().Errorf("Failed to create task: %v", err)
		RespondInternalError(c, "Failed to create task")
		return
	}

	// 转换为指针切片
	packetPtrs := make([]*models.Packet, len(packets))
	for i := range packets {
		packetPtrs[i] = &packets[i]
	}

	// 创建攻击会话
	_ = h.manager.CreateSession(taskID, "replay", req.Interface)

	// 异步执行重放
	go func() {
		ctx := context.Background()
		startTime := time.Now()

		// 创建重放配置
		config := &attack.ReplayConfig{
			Interface:         req.Interface,
			SpeedMultiplier:   req.SpeedMultiplier,
			Mode:              req.Mode,
			LoopCount:         req.LoopCount,
			Duration:          req.Duration,
			PreserveTimestamp: req.PreserveTimestamp,
			ModifyChecksum:    req.ModifyChecksum,
		}

		// 执行重放
		result, err := h.replayer.ReplayPackets(ctx, packetPtrs, config)
		if err != nil {
			logger.GetLogger().Errorf("Replay failed: %v", err)
			totalSent := 0
			totalFailed := len(packets)
			if result != nil {
				totalSent = result.SentCount
				totalFailed = result.FailedCount
			}
			updateTaskStatus(task.ID, "failed", 100, map[string]interface{}{
				"error":         err.Error(),
				"packetsSent":   totalSent,
				"packetsFailed": totalFailed,
				"duration":      time.Since(startTime).String(),
			})
			h.manager.LogAttack("replay", req.Interface, "packet_replay", req.UserID, nil, err.Error(), "failed")
			return
		}

		// 完成
		updateTaskStatus(task.ID, "completed", 100, map[string]interface{}{
			"packetsSent":   result.SentCount,
			"packetsFailed": result.FailedCount,
			"duration":      time.Since(startTime).String(),
		})
		h.manager.LogAttack("replay", req.Interface, "packet_replay", req.UserID, nil, "success", "success")
	}()

	RespondSuccess(c, gin.H{
		"message": "Replay started",
		"taskId":  task.ID,
		"task": gin.H{
			"id":          task.ID,
			"taskId":      taskID,
			"status":      "running",
			"sessionName": session.Name,
		},
	})
}

// StartFuzzing 启动 Fuzzing
func (h *AttackHandler) StartFuzzing(c *gin.Context) {
	var req struct {
		Target           string   `json:"target" binding:"required"`
		Port             int      `json:"port" binding:"required"`
		Protocol         string   `json:"protocol" binding:"required"`
		Template         string   `json:"template"`
		Iterations       int      `json:"iterations"`
		MutationRate     float64  `json:"mutation_rate"`
		MutationStrategy string   `json:"mutation_strategy"`
		Timeout          int      `json:"timeout"`
		Concurrency      int      `json:"concurrency"`
		AnomalyDetection []string `json:"anomaly_detection"`
		UserID           string   `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	// 设置默认值
	if req.Iterations == 0 {
		req.Iterations = 100
	}
	if req.MutationRate == 0 {
		req.MutationRate = 0.1
	}
	if req.Timeout == 0 {
		req.Timeout = 5
	}
	if req.MutationStrategy == "" {
		req.MutationStrategy = "smart"
	}
	if req.Concurrency == 0 {
		req.Concurrency = 1
	}
	if len(req.AnomalyDetection) == 0 {
		req.AnomalyDetection = []string{"timeout", "error"}
	}

	// 检查授权
	if err := h.manager.CheckAuthorization(req.Target, req.UserID); err != nil {
		RespondError(c, 403, "Unauthorized")
		return
	}

	// 创建任务记录
	taskID := generateTaskID()
	target := fmt.Sprintf("%s:%d", req.Target, req.Port)
	task := &models.AttackTask{
		TaskID:   taskID,
		Type:     "fuzzing",
		Target:   target,
		Status:   "running",
		Progress: 0,
		Parameters: models.JSON(map[string]interface{}{
			"target":            req.Target,
			"port":              req.Port,
			"protocol":          req.Protocol,
			"template":          req.Template,
			"iterations":        req.Iterations,
			"mutation_rate":     req.MutationRate,
			"mutation_strategy": req.MutationStrategy,
			"timeout":           req.Timeout,
			"concurrency":       req.Concurrency,
			"anomaly_detection": req.AnomalyDetection,
		}),
		UserID:    req.UserID,
		CreatedAt: time.Now(),
	}

	if err := database.GetDB().Create(task).Error; err != nil {
		logger.GetLogger().Errorf("Failed to create task: %v", err)
		RespondInternalError(c, "Failed to create task")
		return
	}

	// 创建攻击会话
	_ = h.manager.CreateSession(taskID, "fuzzing", target)

	// 异步执行 Fuzzing
	go func() {
		ctx := context.Background()
		startTime := time.Now()

		// 准备配置
		config := &attack.FuzzConfig{
			Target:           req.Target,
			Port:             req.Port,
			Protocol:         req.Protocol,
			Template:         []byte(req.Template),
			Iterations:       req.Iterations,
			MutationRate:     req.MutationRate,
			MutationStrategy: req.MutationStrategy,
			Timeout:          time.Duration(req.Timeout) * time.Second,
			Concurrency:      req.Concurrency,
			AnomalyDetection: req.AnomalyDetection,
		}

		// 执行 Fuzzing
		results, err := h.fuzzer.Fuzz(ctx, config)
		if err != nil {
			logger.GetLogger().Errorf("Fuzzing failed: %v", err)
			updateTaskStatus(task.ID, "failed", 100, map[string]interface{}{
				"error":    err.Error(),
				"duration": time.Since(startTime).String(),
			})
			h.manager.LogAttack("fuzzing", target, "protocol_fuzzing", req.UserID, nil, err.Error(), "failed")
			return
		}

		// 统计异常
		anomalyCount := 0
		for _, result := range results {
			if result.Anomaly {
				anomalyCount++
			}
		}

		// 完成
		updateTaskStatus(task.ID, "completed", 100, map[string]interface{}{
			"iterations": len(results),
			"anomalies":  anomalyCount,
			"results":    results,
			"duration":   time.Since(startTime).String(),
		})
		h.manager.LogAttack("fuzzing", target, "protocol_fuzzing", req.UserID, nil, "success", "success")
	}()

	RespondSuccess(c, gin.H{
		"message": "Fuzzing started",
		"taskId":  task.ID,
		"task": gin.H{
			"id":     task.ID,
			"taskId": taskID,
			"status": "running",
			"target": target,
		},
	})
}

// GetTasks 获取任务列表（支持分页）
func (h *AttackHandler) GetTasks(c *gin.Context) {
	db := database.GetDB()

	// 获取分页参数
	params := GetPaginationParams(c)

	// 查询参数
	taskType := c.Query("type")
	status := c.Query("status")

	// 构建查询
	query := db.Model(&models.AttackTask{})
	if taskType != "" {
		query = query.Where("type = ?", taskType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	// 查询总数
	var total int64
	query.Count(&total)

	// 查询任务列表
	var tasks []models.AttackTask
	query.Order("id DESC").
		Offset(params.GetOffset()).
		Limit(params.GetLimit()).
		Find(&tasks)

	// 计算元数据
	meta := CalculateMeta(total, params.Page, params.PageSize)

	// 返回标准响应
	RespondSuccessWithMeta(c, gin.H{"tasks": tasks}, meta)
}

// GetTask 获取任务详情
func (h *AttackHandler) GetTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	RespondSuccess(c, gin.H{
		"task": task,
	})
}

// StopTask 停止任务
func (h *AttackHandler) StopTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	if task.Status != "running" {
		RespondBadRequest(c, "Task is not running")
		return
	}

	// 停止攻击会话
	if err := h.manager.StopSession(task.TaskID); err != nil {
		logger.GetLogger().Warnf("Failed to stop session: %v", err)
	}

	// 更新任务状态
	updateTaskStatus(task.ID, "stopped", task.Progress, nil)

	RespondSuccess(c, gin.H{"message": "Task stopped"})
}

// DeleteTask 删除任务
func (h *AttackHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	if task.Status == "running" {
		RespondBadRequest(c, "Cannot delete running task")
		return
	}

	if err := database.GetDB().Delete(&task).Error; err != nil {
		RespondInternalError(c, "Failed to delete task")
		return
	}

	RespondSuccess(c, gin.H{"message": "Task deleted"})
}

// BatchDeleteTasks 批量删除任务
func (h *AttackHandler) BatchDeleteTasks(c *gin.Context) {
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
	database.GetDB().Model(&models.AttackTask{}).
		Where("id IN ? AND status = ?", req.TaskIDs, "running").
		Count(&runningCount)

	if runningCount > 0 {
		RespondBadRequest(c, "Cannot delete running tasks")
		return
	}

	// 批量删除
	result := database.GetDB().Where("id IN ?", req.TaskIDs).Delete(&models.AttackTask{})
	if result.Error != nil {
		RespondInternalError(c, "Failed to delete tasks")
		return
	}

	RespondSuccess(c, gin.H{
		"message": "Tasks deleted successfully",
		"deleted": result.RowsAffected,
	})
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func generateTaskID() string {
	return fmt.Sprintf("attack-%d", time.Now().Unix())
}

func updateTaskProgress(taskID uint, progress int) {
	database.GetDB().Model(&models.AttackTask{}).Where("id = ?", taskID).Update("progress", progress)
}

func updateTaskStatus(taskID uint, status string, progress int, result map[string]interface{}) {
	updates := map[string]interface{}{
		"status":   status,
		"progress": progress,
	}
	if result != nil {
		updates["result"] = models.JSON(result)
	}
	if status == "completed" || status == "failed" || status == "stopped" {
		updates["completed_at"] = time.Now()
	}
	database.GetDB().Model(&models.AttackTask{}).Where("id = ?", taskID).Updates(updates)
}
