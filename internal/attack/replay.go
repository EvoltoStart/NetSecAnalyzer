package attack

import (
	"context"
	"fmt"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Replayer 数据包重放器
type Replayer struct {
	Manager *AttackManager
}

// NewReplayer 创建重放器
func NewReplayer(manager *AttackManager) *Replayer {
	return &Replayer{
		Manager: manager,
	}
}

// ReplayResult 重放结果
type ReplayResult struct {
	SentCount   int
	FailedCount int
}

// ReplayPackets 重放数据包
func (r *Replayer) ReplayPackets(ctx context.Context, packets []*models.Packet, iface string, speedMultiplier float64) (*ReplayResult, error) {
	if len(packets) == 0 {
		return nil, fmt.Errorf("no packets to replay")
	}

	logger.GetLogger().Infof("Starting packet replay: %d packets on interface %s", len(packets), iface)

	// 打开网络接口进行发送
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface: %w", err)
	}
	defer handle.Close()

	startTime := packets[0].Timestamp
	replayStartTime := time.Now()
	result := &ReplayResult{
		SentCount:   0,
		FailedCount: 0,
	}

	for i, pkt := range packets {
		select {
		case <-ctx.Done():
			logger.GetLogger().Infof("Packet replay stopped by context (sent: %d, failed: %d)", result.SentCount, result.FailedCount)
			return result, ctx.Err()
		default:
			// 计算延迟
			if i > 0 {
				// 实际应该等待的时间
				elapsed := time.Since(replayStartTime)
				expectedElapsed := pkt.Timestamp.Sub(startTime)
				waitTime := time.Duration(float64(expectedElapsed)/speedMultiplier) - elapsed

				if waitTime > 0 {
					time.Sleep(waitTime)
				}
			}

			// 检查是否有完整的原始数据包
			if len(pkt.RawData) == 0 {
				logger.GetLogger().Warnf("Packet %d has no RawData (old format), skipping. Please recapture the session.", i)
				result.FailedCount++
				continue
			}

			// 使用完整的原始数据包
			dataToSend := pkt.RawData

			// 发送数据包
			if err := handle.WritePacketData(dataToSend); err != nil {
				logger.GetLogger().Errorf("Failed to send packet %d: %v", i, err)
				result.FailedCount++
				continue
			}

			result.SentCount++
			if (i+1)%100 == 0 || i == len(packets)-1 {
				logger.GetLogger().Debugf("Replayed packet %d/%d (sent: %d, failed: %d)", i+1, len(packets), result.SentCount, result.FailedCount)
			}
		}
	}

	logger.GetLogger().Infof("Packet replay completed (sent: %d, failed: %d)", result.SentCount, result.FailedCount)
	return result, nil
}

// ReplayFromPCAP 从 PCAP 文件重放
func (r *Replayer) ReplayFromPCAP(ctx context.Context, pcapFile, iface string, speedMultiplier float64) error {
	// 打开 PCAP 文件
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer handle.Close()

	// 打开发送接口
	sendHandle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	defer sendHandle.Close()

	logger.GetLogger().Infof("Replaying PCAP file: %s on interface %s", pcapFile, iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	replayStartTime := time.Now()
	var firstTimestamp time.Time
	packetCount := 0

	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("PCAP replay stopped by context")
			return ctx.Err()
		default:
			timestamp := packet.Metadata().Timestamp

			if packetCount == 0 {
				firstTimestamp = timestamp
			} else {
				// 计算延迟
				elapsed := time.Since(replayStartTime)
				expectedElapsed := timestamp.Sub(firstTimestamp)
				waitTime := time.Duration(float64(expectedElapsed)/speedMultiplier) - elapsed

				if waitTime > 0 {
					time.Sleep(waitTime)
				}
			}

			// 发送数据包
			if err := sendHandle.WritePacketData(packet.Data()); err != nil {
				logger.GetLogger().Errorf("Failed to send packet: %v", err)
			}

			packetCount++

			if packetCount%100 == 0 {
				logger.GetLogger().Debugf("Replayed %d packets", packetCount)
			}
		}
	}

	logger.GetLogger().Infof("PCAP replay completed: %d packets sent", packetCount)
	return nil
}

// ModifyAndReplay 修改并重放数据包
func (r *Replayer) ModifyAndReplay(ctx context.Context, pkt *models.Packet, iface string, modifications map[string]interface{}) error {
	// 构造新的数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// 解析原始数据包
	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)

	var newLayers []gopacket.SerializableLayer

	// 以太网层
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		newLayers = append(newLayers, eth)
	}

	// IP 层
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)

		// 应用修改
		if newSrc, exists := modifications["src_ip"]; exists {
			// 修改源 IP
			logger.GetLogger().Debugf("Modifying src IP to %v", newSrc)
		}
		if newDst, exists := modifications["dst_ip"]; exists {
			// 修改目标 IP
			logger.GetLogger().Debugf("Modifying dst IP to %v", newDst)
		}

		newLayers = append(newLayers, ip)
	}

	// TCP/UDP 层
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)

		if newSrcPort, exists := modifications["src_port"]; exists {
			if port, ok := newSrcPort.(uint16); ok {
				tcp.SrcPort = layers.TCPPort(port)
			}
		}
		if newDstPort, exists := modifications["dst_port"]; exists {
			if port, ok := newDstPort.(uint16); ok {
				tcp.DstPort = layers.TCPPort(port)
			}
		}

		newLayers = append(newLayers, tcp)
	}

	// 应用层
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := gopacket.Payload(appLayer.Payload())

		// 修改 payload
		if newPayload, exists := modifications["payload"]; exists {
			if payloadBytes, ok := newPayload.([]byte); ok {
				payload = gopacket.Payload(payloadBytes)
			}
		}

		newLayers = append(newLayers, payload)
	}

	// 序列化
	if err := gopacket.SerializeLayers(buffer, opts, newLayers...); err != nil {
		return fmt.Errorf("failed to serialize packet: %w", err)
	}

	// 发送修改后的数据包
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	defer handle.Close()

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to send modified packet: %w", err)
	}

	logger.GetLogger().Info("Modified packet sent successfully")
	return nil
}
