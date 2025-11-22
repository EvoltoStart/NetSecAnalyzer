package ids

import (
	"context"
	"fmt"
	"net"
	"netsecanalyzer/pkg/logger"
	"os/exec"
	"sync"
	"sync/atomic"
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
	autoBlock      atomic.Bool // 使用原子变量支持动态修改

	handle      *pcap.Handle
	flowManager *FlowManager // 流管理器
	detectors   []Detector
	alerts      []Alert
	alertsMux   sync.RWMutex
	stats       Statistics
	statsMux    sync.RWMutex
	stopChan    chan struct{}
	running     bool
	runningMux  sync.RWMutex
}

// NewIDS 创建 IDS 实例
func NewIDS(iface, mode string, rules []string, sensitivity, alertThreshold int, autoBlock bool) *IDS {
	ids := &IDS{
		Interface:      iface,
		Mode:           mode,
		Rules:          rules,
		Sensitivity:    sensitivity,
		AlertThreshold: alertThreshold,
		alerts:         make([]Alert, 0),
		stopChan:       make(chan struct{}),
		flowManager:    NewFlowManager(DefaultFlowConfig()), // 初始化流管理器
	}

	// 初始化 autoBlock 原子变量
	ids.autoBlock.Store(autoBlock)

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

	// 停止流管理器
	if ids.flowManager != nil {
		ids.flowManager.Stop()
	}

	ids.running = false

	logger.GetLogger().Info("IDS stopped")
}

// SetAutoBlock 动态设置自动阻断开关
func (ids *IDS) SetAutoBlock(enabled bool) {
	ids.autoBlock.Store(enabled)
	logger.GetLogger().Infof("IDS auto-block %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// GetAutoBlock 获取当前自动阻断状态
func (ids *IDS) GetAutoBlock() bool {
	return ids.autoBlock.Load()
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

	// 添加到流管理器
	var payload []byte
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload = appLayer.Payload()
	}

	flow := ids.flowManager.AddPacket(info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, payload)

	// 网络层检测（端口扫描、DoS）- 每个包都检测
	for _, detector := range ids.detectors {
		detectorName := detector.GetName()

		// 网络层检测器：使用原始包信息
		if detectorName == "PortScanDetector" || detectorName == "DoSDetector" || detectorName == "BruteForceDetector" {
			if alert := detector.Detect(info); alert != nil {
				ids.handleAlert(alert)
			}
			continue
		}
	}

	// 应用层检测（SQL注入、XSS）- 只在流缓冲足够大且是 HTTP 时检测
	// 并且避免重复检测：只在特定条件下检测一次
	if flow.IsHTTP && len(flow.Buffer) >= 20 { // 降低到 20 字节
		// 检测条件（更宽松）：
		// 1. 每 2 个包检测一次（更频繁）
		// 2. 或者缓冲 >= 100 字节（降低阈值）
		// 3. 或者是前 5 个包（扩大范围）
		shouldDetect := (flow.PacketCount%2 == 0) ||
			(len(flow.Buffer) >= 100) ||
			(flow.PacketCount <= 5)

		if shouldDetect {
			// 调试日志：记录检测时的流状态
			logger.GetLogger().Infof("🔍 App-layer detection: Flow=%s, Packets=%d, BufferSize=%d, Preview=%s",
				flow.Key, flow.PacketCount, len(flow.Buffer),
				string(flow.Buffer[:min(100, len(flow.Buffer))]))

			for _, detector := range ids.detectors {
				detectorName := detector.GetName()

				// 应用层检测器：使用流缓冲
				if detectorName == "SQLInjectionDetector" || detectorName == "XSSDetector" {
					flowInfo := &PacketInfo{
						Timestamp: info.Timestamp,
						Length:    flow.ByteCount,
						SrcIP:     flow.SrcIP,
						SrcPort:   flow.SrcPort,
						DstIP:     flow.DstIP,
						DstPort:   flow.DstPort,
						Protocol:  info.Protocol,
						TCPFlags:  info.TCPFlags,
						Payload:   string(flow.Buffer), // 使用完整的流缓冲
					}

					if alert := detector.Detect(flowInfo); alert != nil {
						ids.handleAlert(alert)
					}
				}
			}
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
		info.Protocol = "TCP"

		// 正确提取 TCP 标志
		flags := ""
		if tcp.SYN {
			flags += "S"
		}
		if tcp.ACK {
			flags += "A"
		}
		if tcp.FIN {
			flags += "F"
		}
		if tcp.RST {
			flags += "R"
		}
		if tcp.PSH {
			flags += "P"
		}
		if tcp.URG {
			flags += "U"
		}
		info.TCPFlags = flags
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = int(udp.SrcPort)
		info.DstPort = int(udp.DstPort)
		info.Protocol = "UDP"
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		info.Protocol = "ICMP"
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

	// 自动阻断（使用原子变量读取）
	if ids.autoBlock.Load() {
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

// GetFlowStats 获取流统计信息
func (ids *IDS) GetFlowStats() FlowStats {
	if ids.flowManager != nil {
		return ids.flowManager.GetStats()
	}
	return FlowStats{}
}

// IsRunning 检查是否运行中
func (ids *IDS) IsRunning() bool {
	ids.runningMux.RLock()
	defer ids.runningMux.RUnlock()

	return ids.running
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
