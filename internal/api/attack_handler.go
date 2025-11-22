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
	manager     *attack.AttackManager
	replayer    *attack.Replayer
	fuzzer      *attack.Fuzzer
	taskManager *attack.TaskManager
	semaphore   chan struct{} // 限制并发任务数量
}

// NewAttackHandler 创建攻击处理器
func NewAttackHandler(m *attack.AttackManager) *AttackHandler {
	return &AttackHandler{
		manager:     m,
		replayer:    attack.NewReplayer(m),
		fuzzer:      attack.NewFuzzer(m),
		taskManager: attack.NewTaskManager(),
		semaphore:   make(chan struct{}, 10), // 最多10个并发任务
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

	// 检查数据包数量（使用独立的查询，避免消耗原query）
	var packetCount int64
	countQuery := database.GetDB().Model(&models.Packet{}).Where("session_id = ?", req.SessionID)
	if req.ProtocolFilter != "" {
		countQuery = countQuery.Where("protocol = ?", req.ProtocolFilter)
	}
	if req.SrcAddrFilter != "" {
		countQuery = countQuery.Where("src_addr = ?", req.SrcAddrFilter)
	}
	if req.DstAddrFilter != "" {
		countQuery = countQuery.Where("dst_addr = ?", req.DstAddrFilter)
	}
	countQuery.Count(&packetCount)

	if packetCount == 0 {
		RespondNotFound(c, "No packets found")
		return
	}

	// 限制最大数据包数量，防止内存溢出
	const maxPackets = 50000
	if packetCount > maxPackets {
		logger.GetLogger().Warnf("Session has %d packets, limiting to %d", packetCount, maxPackets)
		RespondError(c, 400, fmt.Sprintf("Too many packets (%d). Maximum allowed is %d. Please use filters to reduce the packet count.", packetCount, maxPackets))
		return
	}

	// 获取过滤后的数据包
	var packets []models.Packet
	query.Find(&packets)

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

	// 检查并发限制
	select {
	case h.semaphore <- struct{}{}:
		// 获取到信号量，继续执行
	default:
		// 并发任务已满
		logger.GetLogger().Warnf("Too many concurrent tasks, rejecting new replay task")
		RespondError(c, 429, "Too many concurrent tasks. Please wait for existing tasks to complete.")
		return
	}

	// 异步执行重放
	go func() {
		defer func() { <-h.semaphore }() // 释放信号量
		// 创建可取消的context，添加30分钟超时保护
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		// 注册任务到管理器
		h.taskManager.AddTask(task.ID, cancel)
		defer h.taskManager.RemoveTask(task.ID)

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

		// 检查是否被取消
		if ctx.Err() == context.Canceled {
			logger.GetLogger().Infof("Replay task %d was stopped by user", task.ID)
			// 保存已完成的结果
			totalSent := 0
			totalFailed := 0
			if result != nil {
				totalSent = result.SentCount
				totalFailed = result.FailedCount
			}
			updateTaskStatus(task.ID, "stopped", 100, map[string]interface{}{
				"packetsSent":   totalSent,
				"packetsFailed": totalFailed,
				"duration":      time.Since(startTime).String(),
				"message":       "Stopped by user",
			})
			h.manager.LogAttack("replay", req.Interface, "packet_replay", req.UserID, nil, "stopped", "stopped")
			return
		}
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
	// 限制最大迭代次数，防止内存溢出
	const maxIterations = 100000
	if req.Iterations > maxIterations {
		logger.GetLogger().Warnf("Iterations %d exceeds maximum %d, limiting", req.Iterations, maxIterations)
		RespondError(c, 400, fmt.Sprintf("Iterations cannot exceed %d. Please use a smaller value.", maxIterations))
		return
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

	// 检查并发限制
	select {
	case h.semaphore <- struct{}{}:
		// 获取到信号量，继续执行
	default:
		// 并发任务已满
		logger.GetLogger().Warnf("Too many concurrent tasks, rejecting new fuzzing task")
		RespondError(c, 429, "Too many concurrent tasks. Please wait for existing tasks to complete.")
		return
	}

	// 异步执行 Fuzzing
	go func() {
		defer func() { <-h.semaphore }() // 释放信号量
		// 创建可取消的context，添加1小时超时保护
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
		defer cancel()

		// 注册任务到管理器
		h.taskManager.AddTask(task.ID, cancel)
		defer h.taskManager.RemoveTask(task.ID)

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

		// 检查是否被取消
		if ctx.Err() == context.Canceled {
			logger.GetLogger().Infof("Fuzzing task %d was stopped by user", task.ID)
			// 保存已完成的结果 - 只保存异常结果
			anomalyCount := 0
			anomalyResults := make([]*attack.FuzzResult, 0)
			for _, result := range results {
				if result.Anomaly {
					anomalyCount++
					if len(anomalyResults) < 100 { // 限制数量
						anomalyResults = append(anomalyResults, result)
					}
				}
			}
			updateTaskStatus(task.ID, "stopped", 100, map[string]interface{}{
				"iterations":       len(results),
				"anomalies":        anomalyCount,
				"anomalyResults":   anomalyResults,
				"duration":         time.Since(startTime).String(),
				"message":          "Stopped by user",
				"resultsTruncated": len(anomalyResults) < anomalyCount,
			})
			h.manager.LogAttack("fuzzing", target, "protocol_fuzzing", req.UserID, nil, "stopped", "stopped")
			return
		}

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

		// 完成 - 只保存异常结果和摘要，避免数据库字段过大
		anomalyResults := make([]*attack.FuzzResult, 0)
		for _, result := range results {
			if result.Anomaly {
				anomalyResults = append(anomalyResults, result)
			}
		}

		// 限制保存的结果数量
		const maxSavedResults = 100
		if len(anomalyResults) > maxSavedResults {
			logger.GetLogger().Warnf("Too many anomaly results (%d), limiting to %d", len(anomalyResults), maxSavedResults)
			anomalyResults = anomalyResults[:maxSavedResults]
		}

		updateTaskStatus(task.ID, "completed", 100, map[string]interface{}{
			"iterations":       len(results),
			"anomalies":        anomalyCount,
			"anomalyResults":   anomalyResults, // 只保存异常结果
			"duration":         time.Since(startTime).String(),
			"resultsTruncated": len(anomalyResults) < anomalyCount,
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
	taskIDStr := c.Param("id")
	var taskID uint
	if _, err := fmt.Sscanf(taskIDStr, "%d", &taskID); err != nil {
		RespondBadRequest(c, "Invalid task ID")
		return
	}

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	if task.Status != "running" {
		RespondBadRequest(c, "Task is not running")
		return
	}

	// 停止任务（通过取消context）
	if h.taskManager.StopTask(taskID) {
		logger.GetLogger().Infof("Stopping task %d via context cancellation", taskID)
	}

	// 注意：不在这里更新状态，让异步任务自己更新为stopped状态并保存结果

	RespondSuccess(c, gin.H{
		"message": "Task stop signal sent",
		"taskId":  taskID,
	})
}

// DeleteTask 删除任务
// 注意: 不能删除正在运行的任务，必须先停止
func (h *AttackHandler) DeleteTask(c *gin.Context) {
	taskIDStr := c.Param("id")
	var taskID uint
	if _, err := fmt.Sscanf(taskIDStr, "%d", &taskID); err != nil {
		RespondBadRequest(c, "Invalid task ID")
		return
	}

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	// 双重检查：数据库状态 + TaskManager 状态
	if task.Status == "running" || h.taskManager.IsRunning(taskID) {
		RespondBadRequest(c, "Cannot delete running task. Please stop it first.")
		return
	}

	// 确保从 TaskManager 中移除（防止遗漏）
	if h.taskManager.IsRunning(taskID) {
		h.taskManager.StopTask(taskID)
		logger.GetLogger().Warnf("Task %d was still in TaskManager, stopped before deletion", taskID)
	}

	if err := database.GetDB().Delete(&task).Error; err != nil {
		RespondInternalError(c, "Failed to delete task")
		return
	}

	logger.GetLogger().Infof("Task %d deleted successfully", taskID)
	RespondSuccess(c, gin.H{"message": "Task deleted"})
}

// BatchDeleteTasks 批量删除任务
// 注意: 不能删除正在运行的任务，必须先停止
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

	// 双重检查：数据库状态 + TaskManager 状态
	var runningCount int64
	database.GetDB().Model(&models.AttackTask{}).
		Where("id IN ? AND status = ?", req.TaskIDs, "running").
		Count(&runningCount)

	// 检查 TaskManager 中是否有正在运行的任务
	runningInManager := 0
	for _, taskID := range req.TaskIDs {
		if h.taskManager.IsRunning(taskID) {
			runningInManager++
		}
	}

	if runningCount > 0 || runningInManager > 0 {
		RespondBadRequest(c, fmt.Sprintf("Cannot delete running tasks (DB: %d, Manager: %d). Please stop them first.", runningCount, runningInManager))
		return
	}

	// 确保从 TaskManager 中清理（防止遗漏）
	cleanedCount := 0
	for _, taskID := range req.TaskIDs {
		if h.taskManager.IsRunning(taskID) {
			h.taskManager.StopTask(taskID)
			cleanedCount++
		}
	}
	if cleanedCount > 0 {
		logger.GetLogger().Warnf("Cleaned %d tasks from TaskManager before batch deletion", cleanedCount)
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
