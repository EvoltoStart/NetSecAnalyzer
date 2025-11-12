package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// CANScanner CAN 总线扫描器
type CANScanner struct {
	Interface     string
	Socket        int
	Timeout       time.Duration
	MaxConcurrent int
	Progress      func(current, total int)
}

// NewCANScanner 创建 CAN 扫描器
func NewCANScanner(iface string, timeout time.Duration, maxConcurrent int) *CANScanner {
	return &CANScanner{
		Interface:     iface,
		Socket:        -1,
		Timeout:       timeout,
		MaxConcurrent: maxConcurrent,
	}
}

// CANScanResult CAN 扫描结果
type CANScanResult struct {
	Interface     string        `json:"interface"`
	ActiveIDs     []CANIDInfo   `json:"active_ids"`
	TotalFrames   int64         `json:"total_frames"`
	UniqueIDs     int           `json:"unique_ids"`
	ScanDuration  time.Duration `json:"scan_duration"`
	Anomalies     []CANAnomaly  `json:"anomalies"`
	TopologyNodes []CANNode     `json:"topology_nodes"`
}

// CANIDInfo CAN ID 信息
type CANIDInfo struct {
	ID         uint32    `json:"id"`
	IDHex      string    `json:"id_hex"`
	FrameCount int64     `json:"frame_count"`
	DataLength uint8     `json:"data_length"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Frequency  float64   `json:"frequency"` // 帧/秒
	IsExtended bool      `json:"is_extended"`
	IsRTR      bool      `json:"is_rtr"`
	SampleData []byte    `json:"sample_data"`
}

// CANAnomaly CAN 异常
type CANAnomaly struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	CANID       uint32    `json:"can_id,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// CANNode CAN 节点
type CANNode struct {
	NodeID      uint32   `json:"node_id"`
	IDRange     []uint32 `json:"id_range"`
	FrameCount  int64    `json:"frame_count"`
	Description string   `json:"description"`
}

// ScanCANBus 扫描 CAN 总线
func (s *CANScanner) ScanCANBus(ctx context.Context, duration time.Duration) (*CANScanResult, error) {
	startTime := time.Now()

	// 初始化 socket
	if err := s.initSocket(); err != nil {
		return nil, err
	}
	defer s.closeSocket()

	result := &CANScanResult{
		Interface:     s.Interface,
		ActiveIDs:     []CANIDInfo{},
		Anomalies:     []CANAnomaly{},
		TopologyNodes: []CANNode{},
	}

	// ID 统计
	idStats := make(map[uint32]*CANIDInfo)
	var mu sync.Mutex

	logger.GetLogger().Infof("Starting CAN bus scan on %s for %s", s.Interface, duration)

	// 扫描超时
	scanCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	buf := make([]byte, 16)
	frameCount := int64(0)

	for {
		select {
		case <-scanCtx.Done():
			goto ScanComplete
		default:
			// 设置读取超时
			tv := unix.Timeval{Sec: 0, Usec: 100000} // 100ms
			if err := unix.SetsockoptTimeval(s.Socket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
				continue
			}

			n, _, err := unix.Recvfrom(s.Socket, buf, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					continue
				}
				logger.GetLogger().Debugf("Receive error: %v", err)
				continue
			}

			if n >= 16 {
				frameCount++
				s.processCANFrame(buf[:n], idStats, &mu)
			}
		}
	}

ScanComplete:
	// 整理结果
	result.TotalFrames = frameCount
	result.UniqueIDs = len(idStats)
	result.ScanDuration = time.Since(startTime)

	// 转换 ID 统计
	for _, info := range idStats {
		// 计算频率
		duration := info.LastSeen.Sub(info.FirstSeen).Seconds()
		if duration > 0 {
			info.Frequency = float64(info.FrameCount) / duration
		}
		result.ActiveIDs = append(result.ActiveIDs, *info)
	}

	// 检测异常
	result.Anomalies = s.detectAnomalies(idStats)

	// 分析拓扑
	result.TopologyNodes = s.analyzeTopology(idStats)

	logger.GetLogger().Infof("CAN scan completed: %d frames, %d unique IDs, %d anomalies",
		result.TotalFrames, result.UniqueIDs, len(result.Anomalies))

	return result, nil
}

// initSocket 初始化 CAN socket
func (s *CANScanner) initSocket() error {
	sock, err := unix.Socket(unix.AF_CAN, unix.SOCK_RAW, unix.CAN_RAW)
	if err != nil {
		return fmt.Errorf("failed to create CAN socket: %w", err)
	}
	s.Socket = sock

	// 获取接口索引
	iface, err := net.InterfaceByName(s.Interface)
	if err != nil {
		unix.Close(sock)
		return fmt.Errorf("failed to find interface %s: %w", s.Interface, err)
	}

	// 绑定到 CAN 接口
	addr := &unix.SockaddrCAN{Ifindex: iface.Index}
	if err := unix.Bind(sock, addr); err != nil {
		unix.Close(sock)
		return fmt.Errorf("failed to bind to interface: %w", err)
	}

	return nil
}

// closeSocket 关闭 socket
func (s *CANScanner) closeSocket() {
	if s.Socket >= 0 {
		unix.Close(s.Socket)
		s.Socket = -1
	}
}

// processCANFrame 处理 CAN 帧
func (s *CANScanner) processCANFrame(data []byte, idStats map[uint32]*CANIDInfo, mu *sync.Mutex) {
	// 解析 CAN 帧
	canID := binary.LittleEndian.Uint32(data[0:4])
	dlc := data[4]
	frameData := data[8:16]

	// 检查扩展帧和 RTR 标志
	isExtended := (canID & 0x80000000) != 0
	isRTR := (canID & 0x40000000) != 0
	canID = canID & 0x1FFFFFFF // 清除标志位

	mu.Lock()
	defer mu.Unlock()

	info, exists := idStats[canID]
	if !exists {
		info = &CANIDInfo{
			ID:         canID,
			IDHex:      fmt.Sprintf("0x%X", canID),
			FirstSeen:  time.Now(),
			IsExtended: isExtended,
			IsRTR:      isRTR,
			DataLength: dlc,
			SampleData: make([]byte, dlc),
		}
		copy(info.SampleData, frameData[:dlc])
		idStats[canID] = info
	}

	info.FrameCount++
	info.LastSeen = time.Now()
}

// detectAnomalies 检测异常
func (s *CANScanner) detectAnomalies(idStats map[uint32]*CANIDInfo) []CANAnomaly {
	var anomalies []CANAnomaly

	// 检测高频 ID（可能的洪泛攻击）
	for id, info := range idStats {
		if info.Frequency > 1000 { // 超过 1000 帧/秒
			anomalies = append(anomalies, CANAnomaly{
				Type:        "high_frequency",
				Severity:    "warning",
				Description: fmt.Sprintf("High frequency CAN ID detected: %.2f frames/sec", info.Frequency),
				CANID:       id,
				Timestamp:   time.Now(),
			})
		}

		// 检测异常 DLC
		if info.DataLength > 8 {
			anomalies = append(anomalies, CANAnomaly{
				Type:        "invalid_dlc",
				Severity:    "high",
				Description: fmt.Sprintf("Invalid DLC detected: %d bytes", info.DataLength),
				CANID:       id,
				Timestamp:   time.Now(),
			})
		}

		// 检测单次出现的 ID（可能的探测）
		if info.FrameCount == 1 {
			anomalies = append(anomalies, CANAnomaly{
				Type:        "single_occurrence",
				Severity:    "info",
				Description: "CAN ID appeared only once (possible probing)",
				CANID:       id,
				Timestamp:   info.FirstSeen,
			})
		}
	}

	return anomalies
}

// analyzeTopology 分析总线拓扑
func (s *CANScanner) analyzeTopology(idStats map[uint32]*CANIDInfo) []CANNode {
	var nodes []CANNode

	// 简单的节点分组：按 ID 范围分组
	// 通常同一个 ECU 会使用连续的 CAN ID 范围
	nodeGroups := make(map[uint32][]uint32)

	for id := range idStats {
		// 按高 8 位分组（简化的节点识别）
		nodeID := id >> 8
		nodeGroups[nodeID] = append(nodeGroups[nodeID], id)
	}

	for nodeID, ids := range nodeGroups {
		var totalFrames int64
		for _, id := range ids {
			totalFrames += idStats[id].FrameCount
		}

		nodes = append(nodes, CANNode{
			NodeID:      nodeID,
			IDRange:     ids,
			FrameCount:  totalFrames,
			Description: fmt.Sprintf("Node 0x%X with %d CAN IDs", nodeID, len(ids)),
		})
	}

	return nodes
}

// EnumerateCANIDs 枚举 CAN ID（主动扫描）
func (s *CANScanner) EnumerateCANIDs(ctx context.Context, startID, endID uint32) ([]uint32, error) {
	var activeIDs []uint32
	var mu sync.Mutex

	if err := s.initSocket(); err != nil {
		return nil, err
	}
	defer s.closeSocket()

	logger.GetLogger().Infof("Enumerating CAN IDs from 0x%X to 0x%X", startID, endID)

	// 发送测试帧并监听响应
	for id := startID; id <= endID; id++ {
		select {
		case <-ctx.Done():
			return activeIDs, ctx.Err()
		default:
			// 发送 RTR 帧请求数据
			if s.sendRTRFrame(id) {
				mu.Lock()
				activeIDs = append(activeIDs, id)
				mu.Unlock()
				logger.GetLogger().Debugf("Found active CAN ID: 0x%X", id)
			}

			// 限速
			time.Sleep(time.Millisecond * 10)
		}
	}

	logger.GetLogger().Infof("CAN ID enumeration completed: %d active IDs found", len(activeIDs))
	return activeIDs, nil
}

// sendRTRFrame 发送 RTR 帧
func (s *CANScanner) sendRTRFrame(canID uint32) bool {
	// 构造 RTR 帧
	frame := make([]byte, 16)
	rtrID := canID | 0x40000000 // 设置 RTR 标志
	binary.LittleEndian.PutUint32(frame[0:4], rtrID)
	frame[4] = 0 // DLC = 0

	if err := unix.Send(s.Socket, frame, 0); err != nil {
		return false
	}

	// 等待响应（简化实现）
	buf := make([]byte, 16)
	tv := unix.Timeval{Sec: 0, Usec: 50000} // 50ms 超时
	unix.SetsockoptTimeval(s.Socket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	n, _, err := unix.Recvfrom(s.Socket, buf, 0)
	if err == nil && n >= 16 {
		responseID := binary.LittleEndian.Uint32(buf[0:4]) & 0x1FFFFFFF
		return responseID == canID
	}

	return false
}
