package database

import (
	"context"
	"encoding/json"
	"fmt"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gorm.io/gorm"
)

// BatchWriter 批量写入器
type BatchWriter struct {
	db            *gorm.DB
	batchSize     int
	flushInterval time.Duration
	buffer        []*models.Packet
	mu            sync.Mutex
	stopChan      chan struct{}
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	// 新增：重试和 DLQ 配置
	maxRetries    int
	retryDelay    time.Duration
	dlqPath       string
	failedBatches int64 // 失败批次计数
	totalRetries  int64 // 总重试次数
}

// NewBatchWriter 创建批量写入器
func NewBatchWriter(db *gorm.DB, batchSize int, flushInterval time.Duration) *BatchWriter {
	ctx, cancel := context.WithCancel(context.Background())

	//创建 DLQ 目录
	dlqPath := "./data/dlq"
	if err := os.MkdirAll(dlqPath, 0755); err != nil {
		logger.GetLogger().Warnf("Failed to create DLQ directory: %v", err)
	}

	bw := &BatchWriter{
		db:            db,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		buffer:        make([]*models.Packet, 0, batchSize),
		stopChan:      make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
		// 设置重试和 DLQ 参数
		maxRetries:    3,               // 最多重试 3 次
		retryDelay:    1 * time.Second, // 重试延迟 1 秒
		dlqPath:       dlqPath,
		failedBatches: 0,
		totalRetries:  0,
	}

	// 启动定时刷新
	bw.wg.Add(1)
	go bw.autoFlush()

	return bw
}

// Write 写入数据包到缓冲区
func (bw *BatchWriter) Write(packet *models.Packet) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	bw.buffer = append(bw.buffer, packet)

	// 如果缓冲区满了，立即刷新
	if len(bw.buffer) >= bw.batchSize {
		return bw.flushLocked()
	}

	return nil
}

// flushLocked 刷新缓冲区（需要持有锁）
func (bw *BatchWriter) flushLocked() error {
	if len(bw.buffer) == 0 {
		return nil
	}

	// 带重试的批量插入
	var lastErr error
	bufferCopy := make([]*models.Packet, len(bw.buffer))
	copy(bufferCopy, bw.buffer)

	for attempt := 0; attempt <= bw.maxRetries; attempt++ {
		if attempt > 0 {
			// 重试前等待
			logger.GetLogger().Warnf("Retrying batch insert (attempt %d/%d) after %v", attempt, bw.maxRetries, bw.retryDelay)
			time.Sleep(bw.retryDelay)
			bw.totalRetries++
		}

		// 批量插入
		err := bw.db.CreateInBatches(bufferCopy, bw.batchSize).Error
		if err == nil {
			// 成功
			logger.GetLogger().Debugf("Batch inserted %d packets", len(bufferCopy))
			bw.buffer = bw.buffer[:0]
			return nil
		}

		lastErr = err
		logger.GetLogger().Errorf("Failed to batch insert packets (attempt %d/%d): %v", attempt+1, bw.maxRetries+1, err)
	}

	// 所有重试都失败，保存到 DLQ
	if err := bw.saveToDeadLetterQueue(bufferCopy); err != nil {
		logger.GetLogger().Errorf("Failed to save to DLQ: %v", err)
	} else {
		logger.GetLogger().Warnf("Saved %d packets to DLQ after %d failed attempts", len(bufferCopy), bw.maxRetries+1)
	}

	bw.failedBatches++

	// 清空缓冲区（即使失败，也要清空以避免内存泄漏）
	bw.buffer = bw.buffer[:0]

	return fmt.Errorf("batch insert failed after %d retries: %w", bw.maxRetries, lastErr)
}

// saveToDeadLetterQueue 保存失败的批次到死信队列
func (bw *BatchWriter) saveToDeadLetterQueue(packets []*models.Packet) error {
	if len(packets) == 0 {
		return nil
	}

	// 生成 DLQ 文件名（包含时间戳）
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(bw.dlqPath, fmt.Sprintf("failed-batch-%s.json", timestamp))

	// 序列化数据包
	data, err := json.MarshalIndent(packets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal packets: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write DLQ file: %w", err)
	}

	logger.GetLogger().Infof("Saved %d packets to DLQ file: %s", len(packets), filename)
	return nil
}

// Flush 手动刷新缓冲区
func (bw *BatchWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.flushLocked()
}

// autoFlush 自动定时刷新
func (bw *BatchWriter) autoFlush() {
	defer bw.wg.Done()

	ticker := time.NewTicker(bw.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-bw.ctx.Done():
			// 最后刷新一次
			bw.Flush()
			return
		case <-ticker.C:
			bw.Flush()
		}
	}
}

// Close 关闭批量写入器
func (bw *BatchWriter) Close() error {
	bw.cancel()
	bw.wg.Wait()
	return bw.Flush()
}

// GetBufferSize 获取当前缓冲区大小
func (bw *BatchWriter) GetBufferSize() int {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return len(bw.buffer)
}

// 新增：获取统计信息
// GetStats 获取批量写入器统计信息
func (bw *BatchWriter) GetStats() map[string]interface{} {
	bw.mu.Lock()
	defer bw.mu.Unlock()

	return map[string]interface{}{
		"buffer_size":    len(bw.buffer),
		"failed_batches": bw.failedBatches,
		"total_retries":  bw.totalRetries,
		"dlq_path":       bw.dlqPath,
	}
}
