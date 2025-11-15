package analyzer

import (
	"fmt"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"strings"
	"sync"
)

// Analyzer 协议分析器
type Analyzer struct {
	parsers map[string]ProtocolParser
	mu      sync.RWMutex
}

// ProtocolParser 协议解析器接口
type ProtocolParser interface {
	Parse(packet *models.Packet) (*ProtocolInfo, error)
	GetName() string
}

// ProtocolInfo 协议信息
type ProtocolInfo struct {
	Protocol   string                 `json:"protocol"`
	Version    string                 `json:"version,omitempty"`
	Method     string                 `json:"method,omitempty"`
	URI        string                 `json:"uri,omitempty"`
	StatusCode int                    `json:"status_code,omitempty"`
	Headers    map[string]string      `json:"headers,omitempty"`
	Body       string                 `json:"body,omitempty"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
	Summary    string                 `json:"summary"`
	Anomalies  []string               `json:"anomalies,omitempty"`
}

// NewAnalyzer 创建分析器
func NewAnalyzer() *Analyzer {
	a := &Analyzer{
		parsers: make(map[string]ProtocolParser),
	}

	// 注册内置解析器
	a.RegisterParser(&HTTPParser{})
	a.RegisterParser(&HTTPSParser{})
	a.RegisterParser(&DNSParser{})
	a.RegisterParser(&ModbusParser{})
	a.RegisterParser(&FTPParser{})
	a.RegisterParser(&TelnetParser{})

	return a
}

// RegisterParser 注册协议解析器
func (a *Analyzer) RegisterParser(parser ProtocolParser) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.parsers[parser.GetName()] = parser
	logger.GetLogger().Infof("Registered protocol parser: %s", parser.GetName())
}

// Analyze 分析数据包
func (a *Analyzer) Analyze(packet *models.Packet) (*ProtocolInfo, error) {
	if packet == nil {
		return nil, fmt.Errorf("packet is nil")
	}

	// 首先尝试基于端口识别协议
	protocolName := a.identifyProtocol(packet)

	a.mu.RLock()
	parser, exists := a.parsers[protocolName]
	a.mu.RUnlock()

	if exists {
		info, err := parser.Parse(packet)
		if err == nil {
			return info, nil
		}
		logger.GetLogger().Debugf("Failed to parse as %s: %v", protocolName, err)
	}

	// 尝试所有解析器
	a.mu.RLock()
	defer a.mu.RUnlock()

	for name, parser := range a.parsers {
		if name == protocolName {
			continue // 已尝试过
		}
		info, err := parser.Parse(packet)
		if err == nil {
			return info, nil
		}
	}

	// 无法识别协议，返回基本信息
	return &ProtocolInfo{
		Protocol: packet.Protocol,
		Summary: fmt.Sprintf("%s: %s:%d -> %s:%d (%d bytes)",
			packet.Protocol, packet.SrcAddr, packet.SrcPort,
			packet.DstAddr, packet.DstPort, packet.Length),
	}, nil
}

// identifyProtocol 基于端口识别协议
func (a *Analyzer) identifyProtocol(packet *models.Packet) string {
	wellKnownPorts := map[int]string{
		80:   "HTTP",
		443:  "HTTPS",
		53:   "DNS",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		110:  "POP3",
		143:  "IMAP",
		502:  "Modbus",
		3306: "MySQL",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP",
	}

	if proto, exists := wellKnownPorts[packet.DstPort]; exists {
		return proto
	}
	if proto, exists := wellKnownPorts[packet.SrcPort]; exists {
		return proto
	}

	return packet.Protocol
}

// GetSupportedProtocols 获取支持的协议列表
func (a *Analyzer) GetSupportedProtocols() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	protocols := make([]string, 0, len(a.parsers))
	for name := range a.parsers {
		protocols = append(protocols, name)
	}
	return protocols
}

// AnalyzeBatch 批量分析数据包
func (a *Analyzer) AnalyzeBatch(packets []*models.Packet, concurrent int) []*ProtocolInfo {
	if concurrent <= 0 {
		concurrent = 10
	}

	results := make([]*ProtocolInfo, len(packets))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrent)

	for i, pkt := range packets {
		wg.Add(1)
		go func(index int, packet *models.Packet) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			info, err := a.Analyze(packet)
			if err != nil {
				logger.GetLogger().Errorf("Failed to analyze packet %d: %v", index, err)
				return
			}
			results[index] = info
		}(i, pkt)
	}

	wg.Wait()
	return results
}

// DetectAnomalies 检测异常
func (a *Analyzer) DetectAnomalies(info *ProtocolInfo) []string {
	var anomalies []string

	// HTTP 异常检测
	if info.Protocol == "HTTP" {
		if info.StatusCode >= 500 {
			anomalies = append(anomalies, fmt.Sprintf("HTTP server error: %d", info.StatusCode))
		}
		if info.Method == "POST" && len(info.Body) > 1024*1024 {
			anomalies = append(anomalies, "Large POST body detected")
		}
		if strings.Contains(strings.ToLower(info.URI), "script") {
			anomalies = append(anomalies, "Potential XSS in URI")
		}
	}

	// Modbus 异常检测
	if info.Protocol == "Modbus" {
		if fields, ok := info.Fields["exception_code"]; ok && fields != nil {
			anomalies = append(anomalies, "Modbus exception detected")
		}
	}

	return anomalies
}

// GenerateStatistics 生成统计信息
func GenerateStatistics(packets []*models.Packet) map[string]interface{} {
	stats := make(map[string]interface{})
	protocolCount := make(map[string]int)
	var totalBytes int64

	for _, pkt := range packets {
		protocolCount[pkt.Protocol]++
		totalBytes += int64(pkt.Length)
	}

	stats["total_packets"] = len(packets)
	stats["total_bytes"] = totalBytes
	stats["protocol_distribution"] = protocolCount

	if len(packets) > 0 {
		stats["start_time"] = packets[0].Timestamp
		stats["end_time"] = packets[len(packets)-1].Timestamp
		duration := packets[len(packets)-1].Timestamp.Sub(packets[0].Timestamp)
		stats["duration_seconds"] = duration.Seconds()
		if duration.Seconds() > 0 {
			stats["packets_per_second"] = float64(len(packets)) / duration.Seconds()
		}
	}

	return stats
}
