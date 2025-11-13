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
		SessionID       uint    `json:"session_id" binding:"required"`
		Interface       string  `json:"interface" binding:"required"`
		SpeedMultiplier float64 `json:"speed_multiplier"`
		Mode            string  `json:"mode"`
		LoopCount       int     `json:"loop_count"`
		UserID          string  `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
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
		c.JSON(403, gin.H{"error": "Unauthorized"})
		return
	}

	// 获取会话信息
	var session models.CaptureSession
	if err := database.GetDB().First(&session, req.SessionID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Session not found"})
		return
	}

	// 获取数据包
	var packets []models.Packet
	database.GetDB().Where("session_id = ?", req.SessionID).Find(&packets)

	if len(packets) == 0 {
		c.JSON(404, gin.H{"error": "No packets found"})
		return
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
			"session_id":       req.SessionID,
			"session_name":     session.Name,
			"interface":        req.Interface,
			"speed_multiplier": req.SpeedMultiplier,
			"mode":             req.Mode,
			"loop_count":       req.LoopCount,
			"packet_count":     len(packets),
		}),
		UserID:    req.UserID,
		CreatedAt: time.Now(),
	}

	if err := database.GetDB().Create(task).Error; err != nil {
		logger.GetLogger().Errorf("Failed to create task: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create task"})
		return
	}

	// 转换为指针切片
	packetPtrs := make([]*models.Packet, len(packets))
	for i := range packets {
		packetPtrs[i] = &packets[i]
	}

	// 创建攻击会话
	attackSession := h.manager.CreateSession(taskID, "replay", req.Interface)

	// 异步执行重放
	go func() {
		ctx := context.Background()
		startTime := time.Now()
		var totalSent, totalFailed int

		// 根据模式执行
		loopCount := 1
		if req.Mode == "loop" {
			loopCount = req.LoopCount
		}

		for i := 0; i < loopCount; i++ {
			select {
			case <-attackSession.StopChan:
				logger.GetLogger().Info("Replay stopped by user")
				updateTaskStatus(task.ID, "stopped", 100, map[string]interface{}{
					"packets_sent":   totalSent,
					"packets_failed": totalFailed,
					"duration":       time.Since(startTime).String(),
				})
				return
			default:
				if err := h.replayer.ReplayPackets(ctx, packetPtrs, req.Interface, req.SpeedMultiplier); err != nil {
					logger.GetLogger().Errorf("Replay failed: %v", err)
					totalFailed += len(packets)
					updateTaskStatus(task.ID, "failed", 100, map[string]interface{}{
						"error":          err.Error(),
						"packets_sent":   totalSent,
						"packets_failed": totalFailed,
						"duration":       time.Since(startTime).String(),
					})
					h.manager.LogAttack("replay", req.Interface, "packet_replay", req.UserID, nil, err.Error(), "failed")
					return
				}
				totalSent += len(packets)

				// 更新进度
				progress := int(float64(i+1) / float64(loopCount) * 100)
				updateTaskProgress(task.ID, progress)
			}
		}

		// 完成
		updateTaskStatus(task.ID, "completed", 100, map[string]interface{}{
			"packets_sent":   totalSent,
			"packets_failed": totalFailed,
			"duration":       time.Since(startTime).String(),
		})
		h.manager.LogAttack("replay", req.Interface, "packet_replay", req.UserID, nil, "success", "success")
	}()

	c.JSON(200, gin.H{
		"message": "Replay started",
		"data": gin.H{
			"id":           task.ID,
			"task_id":      taskID,
			"status":       "running",
			"session_name": session.Name,
		},
	})
}

// StartFuzzing 启动 Fuzzing
func (h *AttackHandler) StartFuzzing(c *gin.Context) {
	var req struct {
		Target       string  `json:"target" binding:"required"`
		Port         int     `json:"port" binding:"required"`
		Protocol     string  `json:"protocol" binding:"required"`
		Template     string  `json:"template"`
		Iterations   int     `json:"iterations"`
		MutationRate float64 `json:"mutation_rate"`
		Timeout      int     `json:"timeout"`
		UserID       string  `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
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

	// 检查授权
	if err := h.manager.CheckAuthorization(req.Target, req.UserID); err != nil {
		c.JSON(403, gin.H{"error": "Unauthorized"})
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
			"target":        req.Target,
			"port":          req.Port,
			"protocol":      req.Protocol,
			"template":      req.Template,
			"iterations":    req.Iterations,
			"mutation_rate": req.MutationRate,
			"timeout":       req.Timeout,
		}),
		UserID:    req.UserID,
		CreatedAt: time.Now(),
	}

	if err := database.GetDB().Create(task).Error; err != nil {
		logger.GetLogger().Errorf("Failed to create task: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create task"})
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
			Target:       req.Target,
			Port:         req.Port,
			Protocol:     req.Protocol,
			Template:     []byte(req.Template),
			Iterations:   req.Iterations,
			MutationRate: req.MutationRate,
			Timeout:      time.Duration(req.Timeout) * time.Second,
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

	c.JSON(200, gin.H{
		"message": "Fuzzing started",
		"data": gin.H{
			"id":      task.ID,
			"task_id": taskID,
			"status":  "running",
			"target":  target,
		},
	})
}

// GetTasks 获取任务列表
func (h *AttackHandler) GetTasks(c *gin.Context) {
	var tasks []models.AttackTask
	db := database.GetDB()

	// 查询参数
	taskType := c.Query("type")
	status := c.Query("status")

	query := db.Model(&models.AttackTask{})
	if taskType != "" {
		query = query.Where("type = ?", taskType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	query.Order("id DESC").Find(&tasks)

	c.JSON(200, gin.H{
		"data": tasks,
	})
}

// GetTask 获取任务详情
func (h *AttackHandler) GetTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Task not found"})
		return
	}

	c.JSON(200, gin.H{
		"data": task,
	})
}

// StopTask 停止任务
func (h *AttackHandler) StopTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Task not found"})
		return
	}

	if task.Status != "running" {
		c.JSON(400, gin.H{"error": "Task is not running"})
		return
	}

	// 停止攻击会话
	if err := h.manager.StopSession(task.TaskID); err != nil {
		logger.GetLogger().Warnf("Failed to stop session: %v", err)
	}

	// 更新任务状态
	updateTaskStatus(task.ID, "stopped", task.Progress, nil)

	c.JSON(200, gin.H{"message": "Task stopped"})
}

// DeleteTask 删除任务
func (h *AttackHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.AttackTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Task not found"})
		return
	}

	if task.Status == "running" {
		c.JSON(400, gin.H{"error": "Cannot delete running task"})
		return
	}

	if err := database.GetDB().Delete(&task).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete task"})
		return
	}

	c.JSON(200, gin.H{"message": "Task deleted"})
}

// 辅助函数

func generateTaskID() string {
	return fmt.Sprintf("task_%d", time.Now().UnixNano())
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
