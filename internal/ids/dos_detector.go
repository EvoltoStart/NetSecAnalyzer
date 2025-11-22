package ids

import (
	"fmt"
	"sync"
	"time"
)

// DoSDetector DoS 攻击检测器
type DoSDetector struct {
	sensitivity int
	// 记录每个源 IP 的请求频率
	requestHistory map[string]*RequestRecord
	// 记录最近的告警时间（用于去重）
	lastAlertTime map[string]time.Time
	mu            sync.RWMutex
}

// RequestRecord 请求记录
type RequestRecord struct {
	Timestamps []time.Time
	FirstSeen  time.Time
	LastSeen   time.Time
}

// NewDoSDetector 创建 DoS 检测器
func NewDoSDetector(sensitivity int) *DoSDetector {
	detector := &DoSDetector{
		sensitivity:    sensitivity,
		requestHistory: make(map[string]*RequestRecord),
		lastAlertTime:  make(map[string]time.Time),
	}

	// 启动清理协程
	go detector.cleanup()

	return detector
}

// Detect 检测 DoS 攻击
func (d *DoSDetector) Detect(info *PacketInfo) *Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 获取或创建请求记录
	record, exists := d.requestHistory[info.SrcIP]
	if !exists {
		record = &RequestRecord{
			Timestamps: make([]time.Time, 0),
			FirstSeen:  info.Timestamp,
		}
		d.requestHistory[info.SrcIP] = record
	}

	// 添加时间戳
	record.Timestamps = append(record.Timestamps, info.Timestamp)
	record.LastSeen = info.Timestamp

	// 计算时间窗口（根据敏感度调整）
	windowDuration := time.Duration(10/d.sensitivity) * time.Second
	cutoffTime := info.Timestamp.Add(-windowDuration)

	// 清理过期的时间戳
	validTimestamps := make([]time.Time, 0)
	for _, ts := range record.Timestamps {
		if ts.After(cutoffTime) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	record.Timestamps = validTimestamps

	// 计算请求速率
	requestCount := len(record.Timestamps)

	// 根据敏感度设置阈值（改进算法）
	// 敏感度 1-3: 宽松（100-50 req）
	// 敏感度 4-6: 中等（50-30 req）
	// 敏感度 7-10: 严格（30-10 req）
	var threshold int
	if d.sensitivity <= 3 {
		threshold = 100 - (d.sensitivity * 10)
	} else if d.sensitivity <= 6 {
		threshold = 70 - (d.sensitivity * 5)
	} else {
		threshold = 40 - (d.sensitivity * 3)
	}
	// 确保阈值至少为 10
	if threshold < 10 {
		threshold = 10
	}

	// 检查告警去重：同一 IP 在 30 秒内只告警一次
	if lastAlert, exists := d.lastAlertTime[info.SrcIP]; exists {
		if info.Timestamp.Sub(lastAlert) < 30*time.Second {
			return nil // 跳过重复告警
		}
	}

	// 如果请求速率超过阈值，触发告警
	if requestCount >= threshold {
		// 记录告警时间
		d.lastAlertTime[info.SrcIP] = info.Timestamp
		return &Alert{
			Type:        "dos",
			Severity:    d.getSeverity(requestCount),
			Description: fmt.Sprintf("Detected potential DoS attack (%d requests in %v)", requestCount, windowDuration),
			Source:      info.SrcIP,
			Destination: info.DstIP,
			Timestamp:   info.Timestamp,
			Details: map[string]interface{}{
				"request_count": requestCount,
				"time_window":   windowDuration.String(),
				"threshold":     threshold,
				"rate_per_sec":  float64(requestCount) / windowDuration.Seconds(),
			},
		}
	}

	return nil
}

// getSeverity 根据请求数量和敏感度确定严重程度
func (d *DoSDetector) getSeverity(requestCount int) string {
	// 根据敏感度调整严重程度判断
	if d.sensitivity >= 7 {
		// 高敏感度：更容易判定为高危
		if requestCount > 100 {
			return "critical"
		} else if requestCount > 50 {
			return "high"
		} else if requestCount > 20 {
			return "medium"
		}
	} else {
		// 正常敏感度
		if requestCount > 500 {
			return "critical"
		} else if requestCount > 200 {
			return "high"
		} else if requestCount > 100 {
			return "medium"
		}
	}
	return "low"
}

// GetName 获取检测器名称
func (d *DoSDetector) GetName() string {
	return "DoSDetector"
}

// cleanup 定期清理过期记录
func (d *DoSDetector) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for ip, record := range d.requestHistory {
			// 如果记录超过 10 分钟没有更新，删除
			if now.Sub(record.LastSeen) > 10*time.Minute {
				delete(d.requestHistory, ip)
				delete(d.lastAlertTime, ip)
			}
		}
		d.mu.Unlock()
	}
}
