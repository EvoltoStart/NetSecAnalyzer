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
	// 记录最近的告警时间（用于去重）
	lastAlertTime map[string]time.Time
	mu            sync.RWMutex
}

// ScanRecord 扫描记录
type ScanRecord struct {
	TCPPorts  map[int]time.Time // TCP 端口 -> 最后访问时间
	UDPPorts  map[int]time.Time // UDP 端口 -> 最后访问时间
	ICMPCount int               // ICMP 探测次数
	ScanTypes map[string]int    // 扫描类型统计
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewPortScanDetector 创建端口扫描检测器
func NewPortScanDetector(sensitivity int) *PortScanDetector {
	detector := &PortScanDetector{
		sensitivity:   sensitivity,
		scanHistory:   make(map[string]*ScanRecord),
		lastAlertTime: make(map[string]time.Time),
	}

	// 启动清理协程
	go detector.cleanup()

	return detector
}

// Detect 检测端口扫描
func (d *PortScanDetector) Detect(info *PacketInfo) *Alert {
	// 检测 TCP/UDP/ICMP 扫描
	if info.Protocol != "TCP" && info.Protocol != "UDP" && info.Protocol != "ICMP" {
		return nil
	}

	// 识别扫描类型
	scanType := d.identifyScanType(info)

	d.mu.Lock()
	defer d.mu.Unlock()

	// 获取或创建扫描记录
	record, exists := d.scanHistory[info.SrcIP]
	if !exists {
		record = &ScanRecord{
			TCPPorts:  make(map[int]time.Time),
			UDPPorts:  make(map[int]time.Time),
			ScanTypes: make(map[string]int),
			FirstSeen: info.Timestamp,
		}
		d.scanHistory[info.SrcIP] = record
	}

	// 记录访问的端口和扫描类型
	if info.Protocol == "TCP" {
		record.TCPPorts[info.DstPort] = info.Timestamp
	} else if info.Protocol == "UDP" {
		record.UDPPorts[info.DstPort] = info.Timestamp
	} else if info.Protocol == "ICMP" {
		record.ICMPCount++
	}

	if scanType != "" {
		record.ScanTypes[scanType]++
	}
	record.LastSeen = info.Timestamp

	// 计算时间窗口内的端口数量
	windowDuration := time.Duration(60/d.sensitivity) * time.Second
	cutoffTime := info.Timestamp.Add(-windowDuration)

	// 清理过期的端口记录并统计
	recentTCPPorts := 0
	for port, lastSeen := range record.TCPPorts {
		if lastSeen.After(cutoffTime) {
			recentTCPPorts++
		} else {
			delete(record.TCPPorts, port)
		}
	}

	recentUDPPorts := 0
	for port, lastSeen := range record.UDPPorts {
		if lastSeen.After(cutoffTime) {
			recentUDPPorts++
		} else {
			delete(record.UDPPorts, port)
		}
	}

	// 总端口数
	recentPorts := recentTCPPorts + recentUDPPorts

	// 如果有 ICMP 探测，也算作扫描活动
	if record.ICMPCount > 0 {
		recentPorts += record.ICMPCount / 10 // ICMP 权重较低
	}

	// 根据敏感度设置阈值（改进算法）
	// 敏感度越高，阈值越低
	var threshold int
	if d.sensitivity <= 3 {
		threshold = 20 - d.sensitivity // 17-20 个端口
	} else if d.sensitivity <= 6 {
		threshold = 15 - d.sensitivity // 9-12 个端口
	} else {
		threshold = 10 - (d.sensitivity - 6) // 3-7 个端口
	}
	// 确保阈值至少为 3
	if threshold < 3 {
		threshold = 3
	}

	// 检查告警去重：同一 IP 在 60 秒内只告警一次
	if lastAlert, exists := d.lastAlertTime[info.SrcIP]; exists {
		if info.Timestamp.Sub(lastAlert) < 60*time.Second {
			return nil // 跳过重复告警
		}
	}

	// 如果短时间内访问了大量不同端口，触发告警
	if recentPorts >= threshold {
		// 记录告警时间
		d.lastAlertTime[info.SrcIP] = info.Timestamp

		// 确定主要扫描类型
		mainScanType := d.getMainScanType(record.ScanTypes)
		if mainScanType == "" {
			mainScanType = "Port Scan"
		}

		return &Alert{
			Type:        "port_scan",
			Severity:    d.getSeverity(recentPorts),
			Description: fmt.Sprintf("Detected %s (%d TCP + %d UDP ports in %v)", mainScanType, recentTCPPorts, recentUDPPorts, windowDuration),
			Source:      info.SrcIP,
			Destination: info.DstIP,
			Timestamp:   info.Timestamp,
			Details: map[string]interface{}{
				"tcp_ports":      recentTCPPorts,
				"udp_ports":      recentUDPPorts,
				"icmp_count":     record.ICMPCount,
				"total_ports":    recentPorts,
				"time_window":    windowDuration.String(),
				"threshold":      threshold,
				"scan_types":     record.ScanTypes,
				"main_scan_type": mainScanType,
			},
		}
	}

	return nil
}

// getSeverity 根据扫描端口数量和敏感度确定严重程度
func (d *PortScanDetector) getSeverity(portCount int) string {
	if d.sensitivity >= 7 {
		// 高敏感度：更容易判定为高危
		if portCount > 50 {
			return "critical"
		} else if portCount > 20 {
			return "high"
		} else if portCount > 10 {
			return "medium"
		}
	} else {
		// 正常敏感度
		if portCount > 100 {
			return "critical"
		} else if portCount > 50 {
			return "high"
		} else if portCount > 20 {
			return "medium"
		}
	}
	return "low"
}

// GetName 获取检测器名称
func (d *PortScanDetector) GetName() string {
	return "PortScanDetector"
}

// identifyScanType 识别扫描类型
func (d *PortScanDetector) identifyScanType(info *PacketInfo) string {
	switch info.Protocol {
	case "TCP":
		// TCP 扫描类型识别
		flags := info.TCPFlags
		if flags == "S" || flags == "SYN" {
			return "TCP SYN Scan"
		} else if flags == "F" || flags == "FIN" {
			return "TCP FIN Scan"
		} else if flags == "" || flags == "NONE" {
			return "TCP NULL Scan"
		} else if flags == "FPU" || flags == "XMAS" {
			return "TCP Xmas Scan"
		} else if flags == "A" || flags == "ACK" {
			return "TCP ACK Scan"
		} else if flags == "SA" || flags == "SYN-ACK" {
			return "TCP Connect Scan"
		}
		return "TCP Scan"
	case "UDP":
		return "UDP Scan"
	case "ICMP":
		return "ICMP Ping Scan"
	}
	return ""
}

// getMainScanType 获取主要扫描类型
func (d *PortScanDetector) getMainScanType(scanTypes map[string]int) string {
	if len(scanTypes) == 0 {
		return ""
	}

	// 找出出现次数最多的扫描类型
	maxCount := 0
	mainType := ""
	for scanType, count := range scanTypes {
		if count > maxCount {
			maxCount = count
			mainType = scanType
		}
	}

	return mainType
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
				delete(d.lastAlertTime, ip)
			}
		}
		d.mu.Unlock()
	}
}
