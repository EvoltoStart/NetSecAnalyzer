package ids

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// BruteForceDetector 暴力破解检测器
type BruteForceDetector struct {
	sensitivity int
	// 记录每个源 IP 对认证服务的访问
	authAttempts map[string]*AuthRecord
	mu           sync.RWMutex
}

// AuthRecord 认证记录
type AuthRecord struct {
	Attempts   []time.Time
	FirstSeen  time.Time
	LastSeen   time.Time
	TargetPort int
}

// NewBruteForceDetector 创建暴力破解检测器
func NewBruteForceDetector(sensitivity int) *BruteForceDetector {
	detector := &BruteForceDetector{
		sensitivity:  sensitivity,
		authAttempts: make(map[string]*AuthRecord),
	}

	// 启动清理协程
	go detector.cleanup()

	return detector
}

// Detect 检测暴力破解
func (d *BruteForceDetector) Detect(info *PacketInfo) *Alert {
	// 只检测常见的认证服务端口
	if !d.isAuthPort(info.DstPort) {
		return nil
	}

	// 检查 payload 中是否包含认证相关的关键字
	if !d.isAuthTraffic(info.Payload) {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 创建唯一键（源 IP + 目标端口）
	key := fmt.Sprintf("%s:%d", info.SrcIP, info.DstPort)

	// 获取或创建认证记录
	record, exists := d.authAttempts[key]
	if !exists {
		record = &AuthRecord{
			Attempts:   make([]time.Time, 0),
			FirstSeen:  info.Timestamp,
			TargetPort: info.DstPort,
		}
		d.authAttempts[key] = record
	}

	// 添加尝试记录
	record.Attempts = append(record.Attempts, info.Timestamp)
	record.LastSeen = info.Timestamp

	// 计算时间窗口
	windowDuration := time.Duration(60/d.sensitivity) * time.Second
	cutoffTime := info.Timestamp.Add(-windowDuration)

	// 清理过期的尝试记录
	validAttempts := make([]time.Time, 0)
	for _, ts := range record.Attempts {
		if ts.After(cutoffTime) {
			validAttempts = append(validAttempts, ts)
		}
	}
	record.Attempts = validAttempts

	attemptCount := len(record.Attempts)

	// 根据敏感度设置阈值（改进算法，防止负数）
	// 敏感度 1-3: 宽松（12-14 次）
	// 敏感度 4-6: 中等（8-11 次）
	// 敏感度 7-10: 严格（4-7 次）
	var threshold int
	if d.sensitivity <= 3 {
		threshold = 15 - d.sensitivity // 12-14
	} else if d.sensitivity <= 6 {
		threshold = 12 - d.sensitivity // 6-8
	} else {
		threshold = 11 - d.sensitivity // 1-4
	}
	// 确保阈值至少为 3
	if threshold < 3 {
		threshold = 3
	}

	// 如果尝试次数超过阈值，触发告警
	if attemptCount >= threshold {
		return &Alert{
			Type:        "brute_force",
			Severity:    d.getSeverity(attemptCount),
			Description: fmt.Sprintf("Detected brute force attack on port %d (%d attempts in %v)", info.DstPort, attemptCount, windowDuration),
			Source:      info.SrcIP,
			Destination: info.DstIP,
			Timestamp:   info.Timestamp,
			Details: map[string]interface{}{
				"attempt_count": attemptCount,
				"target_port":   info.DstPort,
				"service":       d.getServiceName(info.DstPort),
				"time_window":   windowDuration.String(),
				"threshold":     threshold,
			},
		}
	}

	return nil
}

// isAuthPort 判断是否为认证服务端口
func (d *BruteForceDetector) isAuthPort(port int) bool {
	authPorts := []int{
		21,   // FTP
		22,   // SSH
		23,   // Telnet
		25,   // SMTP
		80,   // HTTP
		110,  // POP3
		143,  // IMAP
		389,  // LDAP
		443,  // HTTPS
		445,  // SMB
		3000, // HTTP Dev
		3306, // MySQL
		3389, // RDP
		5000, // HTTP Dev
		5432, // PostgreSQL
		5900, // VNC
		8000, // HTTP Alt
		8080, // HTTP Alt
		9000, // HTTP Alt
	}

	for _, p := range authPorts {
		if port == p {
			return true
		}
	}
	return false
}

// isAuthTraffic 判断是否为认证流量
func (d *BruteForceDetector) isAuthTraffic(payload string) bool {
	// 必须包含认证相关关键字才判定为认证流量
	keywords := []string{
		"login", "password", "auth", "user",
		"USER", "PASS", "AUTH",
		"Authorization:", "WWW-Authenticate:", // HTTP 认证头
		"username", "passwd", "credential", // 其他认证关键字
	}

	payloadLower := strings.ToLower(payload)
	for _, keyword := range keywords {
		if strings.Contains(payloadLower, strings.ToLower(keyword)) {
			return true
		}
	}

	// ✅ 修复：只有包含认证关键字才返回 true
	// 移除了 "return len(payload) > 0" 的兜底逻辑
	return false
}

// getServiceName 获取服务名称
func (d *BruteForceDetector) getServiceName(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB",
		3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
	}
	if name, ok := services[port]; ok {
		return name
	}
	return "Unknown"
}

// getSeverity 根据尝试次数确定严重程度
func (d *BruteForceDetector) getSeverity(attemptCount int) string {
	if attemptCount > 50 {
		return "critical"
	} else if attemptCount > 30 {
		return "high"
	} else if attemptCount > 15 {
		return "medium"
	}
	return "low"
}

// GetName 获取检测器名称
func (d *BruteForceDetector) GetName() string {
	return "BruteForceDetector"
}

// cleanup 定期清理过期记录
func (d *BruteForceDetector) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for key, record := range d.authAttempts {
			if now.Sub(record.LastSeen) > 10*time.Minute {
				delete(d.authAttempts, key)
			}
		}
		d.mu.Unlock()
	}
}
