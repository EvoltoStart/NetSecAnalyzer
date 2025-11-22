package ids

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"time"
)

// 流表配置常量
const (
	DefaultMaxFlows        = 1000 // 默认最大流数量
	DefaultFlowTimeout     = 30   // 默认流超时时间（秒）
	DefaultCleanupInterval = 10   // 默认清理间隔（秒）
	DefaultMaxBufferSize   = 4096 // 默认每个流最大缓冲（4KB）
)

// FlowConfig 流管理器配置
type FlowConfig struct {
	MaxFlows        int
	FlowTimeout     int
	CleanupInterval int
	MaxBufferSize   int
}

// DefaultFlowConfig 返回默认配置
func DefaultFlowConfig() *FlowConfig {
	return &FlowConfig{
		MaxFlows:        DefaultMaxFlows,
		FlowTimeout:     DefaultFlowTimeout,
		CleanupInterval: DefaultCleanupInterval,
		MaxBufferSize:   DefaultMaxBufferSize,
	}
}

// LightweightFlow 轻量级流
type LightweightFlow struct {
	Key         string        // 流标识 "srcIP:srcPort->dstIP:dstPort"
	SrcIP       string        // 源 IP
	SrcPort     int           // 源端口
	DstIP       string        // 目标 IP
	DstPort     int           // 目标端口
	Buffer      []byte        // 数据缓冲
	LastSeen    time.Time     // 最后活跃时间
	FirstSeen   time.Time     // 首次出现时间
	PacketCount int           // 数据包计数
	ByteCount   int           // 字节计数
	IsHTTP      bool          // 是否为 HTTP 流
	listElement *list.Element // LRU 链表元素
}

// FlowManager 流管理器
type FlowManager struct {
	flows    map[string]*LightweightFlow
	lruList  *list.List
	mu       sync.RWMutex
	config   *FlowConfig
	stopChan chan struct{}
	stats    FlowStats
	statsMu  sync.RWMutex
}

// FlowStats 流统计信息
type FlowStats struct {
	TotalFlows   int64 // 总流数
	ActiveFlows  int   // 当前活跃流数
	ExpiredFlows int64 // 过期流数
	EvictedFlows int64 // 被淘汰的流数
	TotalPackets int64 // 总数据包数
	TotalBytes   int64 // 总字节数
	MemoryUsage  int   // 内存使用（字节）
}

// NewFlowManager 创建流管理器
func NewFlowManager(config *FlowConfig) *FlowManager {
	if config == nil {
		config = DefaultFlowConfig()
	}

	fm := &FlowManager{
		flows:    make(map[string]*LightweightFlow),
		lruList:  list.New(),
		config:   config,
		stopChan: make(chan struct{}),
	}

	// 启动清理协程
	go fm.cleanupLoop()

	return fm
}

// AddPacket 添加数据包到流
func (fm *FlowManager) AddPacket(srcIP string, srcPort int, dstIP string, dstPort int, payload []byte) *LightweightFlow {
	key := fm.makeFlowKey(srcIP, srcPort, dstIP, dstPort)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	flow, exists := fm.flows[key]

	if !exists {
		// 检查流表是否已满
		if len(fm.flows) >= fm.config.MaxFlows {
			// LRU 淘汰最旧的流
			fm.evictOldestLocked()
		}

		// 创建新流
		now := time.Now()
		flow = &LightweightFlow{
			Key:         key,
			SrcIP:       srcIP,
			SrcPort:     srcPort,
			DstIP:       dstIP,
			DstPort:     dstPort,
			Buffer:      make([]byte, 0, fm.config.MaxBufferSize),
			FirstSeen:   now,
			LastSeen:    now,
			PacketCount: 0,
			ByteCount:   0,
		}

		// 添加到流表和 LRU 链表
		fm.flows[key] = flow
		flow.listElement = fm.lruList.PushFront(flow)

		// 更新统计
		fm.updateStatsNewFlow()
	} else {
		// 更新 LRU 位置
		fm.lruList.MoveToFront(flow.listElement)
	}

	// 更新流信息
	flow.LastSeen = time.Now()
	flow.PacketCount++
	flow.ByteCount += len(payload)

	// 追加数据到缓冲（限制大小）
	if len(flow.Buffer) < fm.config.MaxBufferSize && len(payload) > 0 {
		remainingSpace := fm.config.MaxBufferSize - len(flow.Buffer)
		if len(payload) <= remainingSpace {
			flow.Buffer = append(flow.Buffer, payload...)
		} else {
			flow.Buffer = append(flow.Buffer, payload[:remainingSpace]...)
		}
	}

	// 检查是否为 HTTP 流量（持续检查直到确认或超过包数限制）
	// ✅ 不依赖端口，完全通过内容识别
	if !flow.IsHTTP && flow.PacketCount <= 10 {
		// 方法1: 检查当前 payload
		if len(payload) > 0 && isHTTPQuick(payload) {
			flow.IsHTTP = true
			log.Printf("✅ HTTP flow detected (current payload): %s:%d, preview: %s",
				key, dstPort, string(payload[:min(50, len(payload))]))
		}

		// 方法2: 检查累积的缓冲区（处理分片情况）
		if !flow.IsHTTP && len(flow.Buffer) >= 10 && isHTTPQuick(flow.Buffer) {
			flow.IsHTTP = true
			log.Printf("✅ HTTP flow detected (accumulated buffer): %s:%d, preview: %s",
				key, dstPort, string(flow.Buffer[:min(50, len(flow.Buffer))]))
		}

		// 调试：记录未识别的流
		if !flow.IsHTTP && flow.PacketCount == 10 && len(flow.Buffer) > 0 {
			log.Printf("⚠️ Flow NOT identified as HTTP after 10 packets: %s, port=%d, buffer preview: %s",
				key, dstPort, string(flow.Buffer[:min(50, len(flow.Buffer))]))
		}
	}

	// 更新统计
	fm.updateStatsPacket(len(payload))

	return flow
}

// GetFlow 获取流
func (fm *FlowManager) GetFlow(srcIP string, srcPort int, dstIP string, dstPort int) *LightweightFlow {
	key := fm.makeFlowKey(srcIP, srcPort, dstIP, dstPort)

	fm.mu.RLock()
	defer fm.mu.RUnlock()

	return fm.flows[key]
}

// makeFlowKey 生成流标识
func (fm *FlowManager) makeFlowKey(srcIP string, srcPort int, dstIP string, dstPort int) string {
	return fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// evictOldestLocked 淘汰最旧的流（需要持有锁）
func (fm *FlowManager) evictOldestLocked() {
	if fm.lruList.Len() == 0 {
		return
	}

	// 获取最旧的流
	oldest := fm.lruList.Back()
	if oldest != nil {
		flow := oldest.Value.(*LightweightFlow)
		delete(fm.flows, flow.Key)
		fm.lruList.Remove(oldest)

		// 更新统计
		fm.statsMu.Lock()
		fm.stats.EvictedFlows++
		fm.statsMu.Unlock()
	}
}

// cleanupLoop 清理循环
func (fm *FlowManager) cleanupLoop() {
	ticker := time.NewTicker(time.Duration(fm.config.CleanupInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fm.cleanup()
		case <-fm.stopChan:
			return
		}
	}
}

// cleanup 清理超时流
func (fm *FlowManager) cleanup() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	now := time.Now()
	timeout := time.Duration(fm.config.FlowTimeout) * time.Second
	expiredCount := 0

	// 遍历并删除超时流
	for key, flow := range fm.flows {
		if now.Sub(flow.LastSeen) > timeout {
			delete(fm.flows, key)
			if flow.listElement != nil {
				fm.lruList.Remove(flow.listElement)
			}
			expiredCount++
		}
	}

	// 更新统计
	if expiredCount > 0 {
		fm.statsMu.Lock()
		fm.stats.ExpiredFlows += int64(expiredCount)
		fm.statsMu.Unlock()
	}
}

// GetStats 获取统计信息
func (fm *FlowManager) GetStats() FlowStats {
	fm.mu.RLock()
	activeFlows := len(fm.flows)
	memoryUsage := fm.estimateMemoryLocked()
	fm.mu.RUnlock()

	fm.statsMu.RLock()
	stats := fm.stats
	fm.statsMu.RUnlock()

	stats.ActiveFlows = activeFlows
	stats.MemoryUsage = memoryUsage

	return stats
}

// estimateMemoryLocked 估算内存使用（需要持有读锁）
func (fm *FlowManager) estimateMemoryLocked() int {
	total := 0
	for _, flow := range fm.flows {
		// 流结构体开销 + Buffer 大小
		total += 200 + len(flow.Buffer)
	}
	return total
}

// updateStatsNewFlow 更新新流统计
func (fm *FlowManager) updateStatsNewFlow() {
	fm.statsMu.Lock()
	fm.stats.TotalFlows++
	fm.statsMu.Unlock()
}

// updateStatsPacket 更新数据包统计
func (fm *FlowManager) updateStatsPacket(bytes int) {
	fm.statsMu.Lock()
	fm.stats.TotalPackets++
	fm.stats.TotalBytes += int64(bytes)
	fm.statsMu.Unlock()
}

// Stop 停止流管理器
func (fm *FlowManager) Stop() {
	close(fm.stopChan)
}

// Clear 清空所有流
func (fm *FlowManager) Clear() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.flows = make(map[string]*LightweightFlow)
	fm.lruList = list.New()
}

// isHTTPQuick 快速判断是否为 HTTP 流量
func isHTTPQuick(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	dataStr := string(data)

	// 检查 HTTP 请求方法（完整匹配，包括空格）
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, method := range httpMethods {
		if len(dataStr) >= len(method) && dataStr[:len(method)] == method {
			return true
		}
	}

	// 检查 HTTP 响应
	if len(data) >= 5 && dataStr[:5] == "HTTP/" {
		return true
	}

	// 更宽松的匹配：检查是否包含 HTTP 特征
	if len(dataStr) > 10 {
		// 检查常见 HTTP 头部
		if containsAny(dataStr, []string{"HTTP/1.", "Host:", "User-Agent:", "Content-Type:", "Content-Length:"}) {
			return true
		}
	}

	return false
}

// containsAny 检查字符串是否包含任意一个子串
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
	}
	return false
}

// GetFlowCount 获取当前流数量
func (fm *FlowManager) GetFlowCount() int {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return len(fm.flows)
}

// GetConfig 获取配置
func (fm *FlowManager) GetConfig() *FlowConfig {
	return fm.config
}
