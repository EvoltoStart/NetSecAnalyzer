package ids

import (
	"fmt"
	"sync"
	"time"
)

// PortScanDetector 端口扫描检测器
type PortScanDetector struct {
	sensitivity int
	// 记录每个源 IP 访问的目标端口
	scanHistory map[string]*ScanRecord
	mu          sync.RWMutex
}

// ScanRecord 扫描记录
type ScanRecord struct {
	Ports     map[int]time.Time // 端口 -> 最后访问时间
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewPortScanDetector 创建端口扫描检测器
func NewPortScanDetector(sensitivity int) *PortScanDetector {
	detector := &PortScanDetector{
		sensitivity: sensitivity,
		scanHistory: make(map[string]*ScanRecord),
	}

	// 启动清理协程
	go detector.cleanup()

	return detector
}

// Detect 检测端口扫描
func (d *PortScanDetector) Detect(info *PacketInfo) *Alert {
	// 只检测 TCP SYN 包（端口扫描的典型特征）
	if info.Protocol != "TCP" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 获取或创建扫描记录
	record, exists := d.scanHistory[info.SrcIP]
	if !exists {
		record = &ScanRecord{
			Ports:     make(map[int]time.Time),
			FirstSeen: info.Timestamp,
		}
		d.scanHistory[info.SrcIP] = record
	}

	// 记录访问的端口
	record.Ports[info.DstPort] = info.Timestamp
	record.LastSeen = info.Timestamp

	// 计算时间窗口内的端口数量
	windowDuration := time.Duration(60/d.sensitivity) * time.Second
	cutoffTime := info.Timestamp.Add(-windowDuration)

	// 清理过期的端口记录
	recentPorts := 0
	for port, lastSeen := range record.Ports {
		if lastSeen.After(cutoffTime) {
			recentPorts++
		} else {
			delete(record.Ports, port)
		}
	}

	// 根据敏感度设置阈值
	// 敏感度越高，阈值越低
	threshold := 20 - d.sensitivity

	// 如果短时间内访问了大量不同端口，触发告警
	if recentPorts >= threshold {
		return &Alert{
			Type:        "port_scan",
			Severity:    d.getSeverity(recentPorts),
			Description: fmt.Sprintf("Detected port scanning activity (%d ports in %v)", recentPorts, windowDuration),
			Source:      info.SrcIP,
			Destination: info.DstIP,
			Timestamp:   info.Timestamp,
			Details: map[string]interface{}{
				"ports_scanned": recentPorts,
				"time_window":   windowDuration.String(),
				"threshold":     threshold,
			},
		}
	}

	return nil
}

// getSeverity 根据扫描端口数量确定严重程度
func (d *PortScanDetector) getSeverity(portCount int) string {
	if portCount > 100 {
		return "high"
	} else if portCount > 50 {
		return "medium"
	}
	return "low"
}

// GetName 获取检测器名称
func (d *PortScanDetector) GetName() string {
	return "PortScanDetector"
}

// cleanup 定期清理过期记录
func (d *PortScanDetector) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for ip, record := range d.scanHistory {
			// 如果记录超过 10 分钟没有更新，删除
			if now.Sub(record.LastSeen) > 10*time.Minute {
				delete(d.scanHistory, ip)
			}
		}
		d.mu.Unlock()
	}
}
