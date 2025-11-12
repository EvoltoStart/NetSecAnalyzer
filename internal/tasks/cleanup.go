package tasks

import (
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"netsecanalyzer/pkg/storage"
	"time"
)

// CleanupTask 数据清理任务
type CleanupTask struct {
	payloadStorage *storage.PayloadStorage
	retentionDays  int
	stopChan       chan struct{}
}

// NewCleanupTask 创建清理任务
func NewCleanupTask(payloadStorage *storage.PayloadStorage, retentionDays int) *CleanupTask {
	return &CleanupTask{
		payloadStorage: payloadStorage,
		retentionDays:  retentionDays,
		stopChan:       make(chan struct{}),
	}
}

// Start 启动清理任务
func (ct *CleanupTask) Start() {
	// 每天凌晨2点执行清理
	go ct.scheduleCleanup()
}

// Stop 停止清理任务
func (ct *CleanupTask) Stop() {
	close(ct.stopChan)
}

// scheduleCleanup 调度清理任务
func (ct *CleanupTask) scheduleCleanup() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// 启动时先执行一次
	ct.runCleanup()

	for {
		select {
		case <-ct.stopChan:
			return
		case <-ticker.C:
			ct.runCleanup()
		}
	}
}

// runCleanup 执行清理
func (ct *CleanupTask) runCleanup() {
	logger.GetLogger().Info("Starting data cleanup task...")

	// 1. 清理过期的数据包记录
	if err := ct.cleanupOldPackets(); err != nil {
		logger.GetLogger().Errorf("Failed to cleanup old packets: %v", err)
	}

	// 2. 清理过期的 Payload 文件
	if ct.payloadStorage != nil {
		if err := ct.payloadStorage.CleanupOldFiles(); err != nil {
			logger.GetLogger().Errorf("Failed to cleanup old payload files: %v", err)
		}
	}

	// 3. 清理已完成的旧会话
	if err := ct.cleanupOldSessions(); err != nil {
		logger.GetLogger().Errorf("Failed to cleanup old sessions: %v", err)
	}

	// 4. 清理旧的扫描任务
	if err := ct.cleanupOldScanTasks(); err != nil {
		logger.GetLogger().Errorf("Failed to cleanup old scan tasks: %v", err)
	}

	// 5. 清理旧的攻击日志
	if err := ct.cleanupOldAttackLogs(); err != nil {
		logger.GetLogger().Errorf("Failed to cleanup old attack logs: %v", err)
	}

	logger.GetLogger().Info("Data cleanup task completed")
}

// cleanupOldPackets 清理过期的数据包
func (ct *CleanupTask) cleanupOldPackets() error {
	cutoffTime := time.Now().AddDate(0, 0, -ct.retentionDays)

	result := database.GetDB().
		Where("timestamp < ?", cutoffTime).
		Delete(&models.Packet{})

	if result.Error != nil {
		return result.Error
	}

	logger.GetLogger().Infof("Deleted %d old packets", result.RowsAffected)
	return nil
}

// cleanupOldSessions 清理过期的会话
func (ct *CleanupTask) cleanupOldSessions() error {
	cutoffTime := time.Now().AddDate(0, 0, -ct.retentionDays)

	// 只删除已完成或已停止的会话
	result := database.GetDB().
		Where("created_at < ? AND status IN ?", cutoffTime, []string{"completed", "stopped"}).
		Delete(&models.CaptureSession{})

	if result.Error != nil {
		return result.Error
	}

	logger.GetLogger().Infof("Deleted %d old sessions", result.RowsAffected)
	return nil
}

// cleanupOldScanTasks 清理过期的扫描任务
func (ct *CleanupTask) cleanupOldScanTasks() error {
	cutoffTime := time.Now().AddDate(0, 0, -ct.retentionDays)

	result := database.GetDB().
		Where("created_at < ? AND status IN ?", cutoffTime, []string{"completed", "failed"}).
		Delete(&models.ScanTask{})

	if result.Error != nil {
		return result.Error
	}

	logger.GetLogger().Infof("Deleted %d old scan tasks", result.RowsAffected)
	return nil
}

// cleanupOldAttackLogs 清理过期的攻击日志
func (ct *CleanupTask) cleanupOldAttackLogs() error {
	cutoffTime := time.Now().AddDate(0, 0, -ct.retentionDays)

	result := database.GetDB().
		Where("executed_at < ?", cutoffTime).
		Delete(&models.AttackLog{})

	if result.Error != nil {
		return result.Error
	}

	logger.GetLogger().Infof("Deleted %d old attack logs", result.RowsAffected)
	return nil
}

// GetStorageStats 获取存储统计信息
func (ct *CleanupTask) GetStorageStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 数据包数量
	var packetCount int64
	database.GetDB().Model(&models.Packet{}).Count(&packetCount)
	stats["packet_count"] = packetCount

	// 会话数量
	var sessionCount int64
	database.GetDB().Model(&models.CaptureSession{}).Count(&sessionCount)
	stats["session_count"] = sessionCount

	// Payload 文件统计
	if ct.payloadStorage != nil {
		fileCount, fileSize, err := ct.payloadStorage.GetStorageStats()
		if err != nil {
			return nil, err
		}
		stats["payload_file_count"] = fileCount
		stats["payload_total_size"] = fileSize
	}

	return stats, nil
}
