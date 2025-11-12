package database

import (
	"context"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
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
}

// NewBatchWriter 创建批量写入器
func NewBatchWriter(db *gorm.DB, batchSize int, flushInterval time.Duration) *BatchWriter {
	ctx, cancel := context.WithCancel(context.Background())
	bw := &BatchWriter{
		db:            db,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		buffer:        make([]*models.Packet, 0, batchSize),
		stopChan:      make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
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

	// 批量插入
	if err := bw.db.CreateInBatches(bw.buffer, bw.batchSize).Error; err != nil {
		logger.GetLogger().Errorf("Failed to batch insert packets: %v", err)
		return err
	}

	logger.GetLogger().Debugf("Batch inserted %d packets", len(bw.buffer))

	// 清空缓冲区
	bw.buffer = bw.buffer[:0]
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
