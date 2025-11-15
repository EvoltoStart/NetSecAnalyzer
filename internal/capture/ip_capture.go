package capture

import (
	"context"
	"fmt"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// IPCapture IP 网络数据采集
type IPCapture struct {
	Interface   string
	Snaplen     int
	Promisc     bool
	Timeout     time.Duration
	Filter      string
	Handle      *pcap.Handle
	PacketChan  chan *models.Packet
	StopChan    chan struct{}
	mu          sync.Mutex
	isRunning   bool
	SessionID   uint
	PacketCount int64
}

// NewIPCapture 创建 IP 采集实例
func NewIPCapture(iface string, snaplen int, promisc bool, timeout time.Duration, filter string, sessionID uint) *IPCapture {
	return &IPCapture{
		Interface:  iface,
		Snaplen:    snaplen,
		Promisc:    promisc,
		Timeout:    timeout,
		Filter:     filter,
		PacketChan: make(chan *models.Packet, 10000),
		StopChan:   make(chan struct{}),
		SessionID:  sessionID,
	}
}

// Start 启动数据采集
func (c *IPCapture) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.isRunning {
		c.mu.Unlock()
		return fmt.Errorf("capture already running")
	}
	c.isRunning = true
	c.mu.Unlock()

	// 打开网络接口
	handle, err := pcap.OpenLive(c.Interface, int32(c.Snaplen), c.Promisc, c.Timeout)
	if err != nil {
		c.isRunning = false
		return fmt.Errorf("failed to open interface %s: %w", c.Interface, err)
	}
	c.Handle = handle

	// 设置 BPF 过滤器
	if c.Filter != "" {
		if err := handle.SetBPFFilter(c.Filter); err != nil {
			handle.Close()
			c.isRunning = false
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	logger.GetLogger().Infof("IP capture started on interface %s", c.Interface)

	// 启动数据包处理
	go c.capturePackets(ctx)

	return nil
}

// capturePackets 捕获并处理数据包
func (c *IPCapture) capturePackets(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.isRunning = false
		c.mu.Unlock()
		if c.Handle != nil {
			c.Handle.Close()
		}
		close(c.PacketChan)
	}()

	packetSource := gopacket.NewPacketSource(c.Handle, c.Handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("IP capture stopped by context")
			return
		case <-c.StopChan:
			logger.GetLogger().Info("IP capture stopped by signal")
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			c.processPacket(packet)
		}
	}
}

// processPacket 处理单个数据包
func (c *IPCapture) processPacket(packet gopacket.Packet) {
	c.PacketCount++

	pkt := &models.Packet{
		SessionID: c.SessionID,
		Timestamp: packet.Metadata().Timestamp,
		Length:    len(packet.Data()),
	}

	// 解析网络层
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		pkt.Protocol = "IPv4"
		pkt.SrcAddr = ip.SrcIP.String()
		pkt.DstAddr = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		pkt.Protocol = "IPv6"
		pkt.SrcAddr = ip.SrcIP.String()
		pkt.DstAddr = ip.DstIP.String()
	}

	// 解析传输层
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pkt.Protocol = "TCP"
		pkt.SrcPort = int(tcp.SrcPort)
		pkt.DstPort = int(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		pkt.Protocol = "UDP"
		pkt.SrcPort = int(udp.SrcPort)
		pkt.DstPort = int(udp.DstPort)
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		pkt.Protocol = "ICMP"
	}

	// 提取应用层数据
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			// 限制 payload 大小
			maxPayloadSize := 4096
			if len(payload) > maxPayloadSize {
				pkt.Payload = payload[:maxPayloadSize]
			} else {
				pkt.Payload = payload
			}
		}
	}

	// 发送到处理通道
	select {
	case c.PacketChan <- pkt:
	default:
		logger.GetLogger().Warn("Packet channel full, dropping packet")
	}
}

// Stop 停止数据采集
func (c *IPCapture) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return fmt.Errorf("capture not running")
	}

	close(c.StopChan)
	logger.GetLogger().Info("IP capture stop signal sent")
	return nil
}

// IsRunning 检查是否正在运行
func (c *IPCapture) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isRunning
}

// GetStats 获取统计信息
func (c *IPCapture) GetStats() (received, dropped, ifDropped int, err error) {
	if c.Handle == nil {
		return 0, 0, 0, fmt.Errorf("handle not initialized")
	}
	stats, err := c.Handle.Stats()
	if err != nil {
		return 0, 0, 0, err
	}
	return int(stats.PacketsReceived), int(stats.PacketsDropped), int(stats.PacketsIfDropped), nil
}

// SaveToPCAP 保存数据包到 PCAP 文件
func (c *IPCapture) SaveToPCAP(filename string) error {
	// TODO: 实现 PCAP 文件导出功能
	// 需要从数据库或缓存中读取数据包并写入文件
	// 可以使用 github.com/google/gopacket/pcapgo 包
	return fmt.Errorf("not implemented yet")
}

// LoadFromPCAP 从 PCAP 文件加载数据包
func LoadFromPCAP(filename string, sessionID uint) ([]*models.Packet, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer handle.Close()

	var packets []*models.Packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		pkt := &models.Packet{
			SessionID: sessionID,
			Timestamp: packet.Metadata().Timestamp,
			Length:    len(packet.Data()),
		}

		// 解析数据包（同上）
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			pkt.Protocol = "IPv4"
			pkt.SrcAddr = ip.SrcIP.String()
			pkt.DstAddr = ip.DstIP.String()
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			pkt.Protocol = "TCP"
			pkt.SrcPort = int(tcp.SrcPort)
			pkt.DstPort = int(tcp.DstPort)
		}

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			pkt.Payload = appLayer.Payload()
		}

		packets = append(packets, pkt)
	}

	return packets, nil
}

// NetworkInterface 网络接口信息
type NetworkInterface struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// GetAvailableInterfaces 获取可用的网络接口
func GetAvailableInterfaces() ([]NetworkInterface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to find devices: %w", err)
	}

	var interfaces []NetworkInterface
	for _, device := range devices {
		description := device.Description
		if description == "" {
			description = "网络接口"
		}
		interfaces = append(interfaces, NetworkInterface{
			Name:        device.Name,
			Description: description,
		})
	}
	return interfaces, nil
}

// GetAvailableInterfaceNames 获取可用的网络接口名称（兼容旧版本）
func GetAvailableInterfaceNames() ([]string, error) {
	interfaces, err := GetAvailableInterfaces()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names, nil
}
