package ids

import (
	"context"
	"fmt"
	"net"
	"netsecanalyzer/pkg/logger"
	"os/exec"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Alert 告警
type Alert struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Destination string                 `json:"destination"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
}

// Statistics 统计信息
type Statistics struct {
	PacketsProcessed int64
	EventsDetected   int64
	AlertsGenerated  int64
	BlocksExecuted   int64
}

// IDS 入侵检测系统
type IDS struct {
	Interface      string
	Mode           string
	Rules          []string
	Sensitivity    int
	AlertThreshold int
	AutoBlock      bool

	handle     *pcap.Handle
	detectors  []Detector
	alerts     []Alert
	alertsMux  sync.RWMutex
	stats      Statistics
	statsMux   sync.RWMutex
	stopChan   chan struct{}
	running    bool
	runningMux sync.RWMutex
}

// NewIDS 创建 IDS 实例
func NewIDS(iface, mode string, rules []string, sensitivity, alertThreshold int, autoBlock bool) *IDS {
	ids := &IDS{
		Interface:      iface,
		Mode:           mode,
		Rules:          rules,
		Sensitivity:    sensitivity,
		AlertThreshold: alertThreshold,
		AutoBlock:      autoBlock,
		alerts:         make([]Alert, 0),
		stopChan:       make(chan struct{}),
	}

	// 初始化检测器
	ids.initDetectors()

	return ids
}

// initDetectors 初始化检测器
func (ids *IDS) initDetectors() {
	ids.detectors = make([]Detector, 0)

	for _, rule := range ids.Rules {
		switch rule {
		case "port_scan":
			ids.detectors = append(ids.detectors, NewPortScanDetector(ids.Sensitivity))
		case "dos":
			ids.detectors = append(ids.detectors, NewDoSDetector(ids.Sensitivity))
		case "brute_force":
			ids.detectors = append(ids.detectors, NewBruteForceDetector(ids.Sensitivity))
		case "sql_injection":
			ids.detectors = append(ids.detectors, NewSQLInjectionDetector(ids.Sensitivity))
		case "xss":
			ids.detectors = append(ids.detectors, NewXSSDetector(ids.Sensitivity))
		}
	}

	logger.GetLogger().Infof("Initialized %d detectors for rules: %v", len(ids.detectors), ids.Rules)
}

// Start 启动 IDS
func (ids *IDS) Start(ctx context.Context) error {
	ids.runningMux.Lock()
	if ids.running {
		ids.runningMux.Unlock()
		return fmt.Errorf("IDS is already running")
	}
	ids.running = true
	ids.runningMux.Unlock()

	// 打开网络接口
	handle, err := pcap.OpenLive(ids.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		ids.runningMux.Lock()
		ids.running = false
		ids.runningMux.Unlock()
		return fmt.Errorf("failed to open interface %s: %w", ids.Interface, err)
	}
	ids.handle = handle

	logger.GetLogger().Infof("IDS started on interface %s with mode %s", ids.Interface, ids.Mode)

	// 启动数据包处理
	go ids.processPackets(ctx)

	return nil
}

// Stop 停止 IDS
func (ids *IDS) Stop() {
	ids.runningMux.Lock()
	defer ids.runningMux.Unlock()

	if !ids.running {
		return
	}

	close(ids.stopChan)
	if ids.handle != nil {
		ids.handle.Close()
	}
	ids.running = false

	logger.GetLogger().Info("IDS stopped")
}

// processPackets 处理数据包
func (ids *IDS) processPackets(ctx context.Context) {
	packetSource := gopacket.NewPacketSource(ids.handle, ids.handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return
		case <-ids.stopChan:
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			ids.processPacket(packet)
		}
	}
}

// processPacket 处理单个数据包
func (ids *IDS) processPacket(packet gopacket.Packet) {
	// 更新统计
	ids.statsMux.Lock()
	ids.stats.PacketsProcessed++
	ids.statsMux.Unlock()

	// 提取数据包信息
	info := ids.extractPacketInfo(packet)
	if info == nil {
		return
	}

	// 使用所有检测器检测
	for _, detector := range ids.detectors {
		if alert := detector.Detect(info); alert != nil {
			ids.handleAlert(alert)
		}
	}
}

// extractPacketInfo 提取数据包信息
func (ids *IDS) extractPacketInfo(packet gopacket.Packet) *PacketInfo {
	info := &PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	// 提取网络层信息
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.NextHeader.String()
	}

	// 提取传输层信息
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = int(tcp.SrcPort)
		info.DstPort = int(tcp.DstPort)
		info.TCPFlags = fmt.Sprintf("%v", tcp.SYN) + fmt.Sprintf("%v", tcp.ACK) + fmt.Sprintf("%v", tcp.FIN)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = int(udp.SrcPort)
		info.DstPort = int(udp.DstPort)
	}

	// 提取应用层数据
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		info.Payload = string(appLayer.Payload())
	}

	return info
}

// handleAlert 处理告警
func (ids *IDS) handleAlert(alert *Alert) {
	ids.alertsMux.Lock()
	defer ids.alertsMux.Unlock()

	// 添加到告警列表
	ids.alerts = append([]Alert{*alert}, ids.alerts...)
	if len(ids.alerts) > 100 {
		ids.alerts = ids.alerts[:100]
	}

	// 更新统计
	ids.statsMux.Lock()
	ids.stats.AlertsGenerated++
	ids.stats.EventsDetected++
	ids.statsMux.Unlock()

	logger.GetLogger().Warnf("IDS Alert: [%s] %s from %s", alert.Type, alert.Description, alert.Source)

	// 自动阻断
	if ids.AutoBlock {
		ids.blockSource(alert.Source)
	}
}

// blockSource 阻断源地址
func (ids *IDS) blockSource(source string) {
	logger.GetLogger().Infof("Attempting to block source: %s", source)

	// 实际的阻断逻辑 - 添加iptables规则
	if err := ids.addIPTablesRule(source); err != nil {
		logger.GetLogger().Errorf("Failed to block %s with iptables: %v", source, err)
		// 如果iptables失败，尝试应用层阻断
		ids.addToBlockList(source)
	} else {
		logger.GetLogger().Infof("Successfully blocked source with iptables: %s", source)
	}

	ids.statsMux.Lock()
	ids.stats.BlocksExecuted++
	ids.statsMux.Unlock()
}

// addIPTablesRule 添加iptables阻断规则
func (ids *IDS) addIPTablesRule(sourceIP string) error {
	// 检查是否为有效IP地址
	if net.ParseIP(sourceIP) == nil {
		return fmt.Errorf("invalid IP address: %s", sourceIP)
	}

	// 构建iptables命令 - 在INPUT链中添加DROP规则
	cmd := fmt.Sprintf("iptables -I INPUT -s %s -j DROP", sourceIP)

	// 执行系统命令
	if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
		return fmt.Errorf("failed to execute iptables command: %w", err)
	}

	logger.GetLogger().Infof("Added iptables rule: DROP %s", sourceIP)
	return nil
}

// addToBlockList 添加到应用层阻断列表（备用方案）
func (ids *IDS) addToBlockList(sourceIP string) {
	// 这里可以实现应用层的阻断逻辑
	// 例如在数据包处理时直接丢弃来自该IP的包
	logger.GetLogger().Infof("Added %s to application-level block list", sourceIP)
}

// GetRecentAlerts 获取最近的告警
func (ids *IDS) GetRecentAlerts(limit int) []Alert {
	ids.alertsMux.RLock()
	defer ids.alertsMux.RUnlock()

	if limit > len(ids.alerts) {
		limit = len(ids.alerts)
	}

	return ids.alerts[:limit]
}

// GetStatistics 获取统计信息
func (ids *IDS) GetStatistics() Statistics {
	ids.statsMux.RLock()
	defer ids.statsMux.RUnlock()

	return ids.stats
}

// IsRunning 检查是否运行中
func (ids *IDS) IsRunning() bool {
	ids.runningMux.RLock()
	defer ids.runningMux.RUnlock()

	return ids.running
}
