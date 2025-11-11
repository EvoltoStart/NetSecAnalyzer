package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// CANCapture CAN 总线数据采集
type CANCapture struct {
	Interface   string
	Socket      int
	PacketChan  chan *models.Packet
	StopChan    chan struct{}
	mu          sync.Mutex
	isRunning   bool
	SessionID   uint
	PacketCount int64
}

// CANFrame CAN 帧结构
type CANFrame struct {
	ID   uint32
	DLC  uint8
	Data [8]byte
}

// NewCANCapture 创建 CAN 采集实例
func NewCANCapture(iface string, sessionID uint) *CANCapture {
	return &CANCapture{
		Interface:  iface,
		Socket:     -1,
		PacketChan: make(chan *models.Packet, 1000),
		StopChan:   make(chan struct{}),
		SessionID:  sessionID,
	}
}

// Start 启动 CAN 数据采集
func (c *CANCapture) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.isRunning {
		c.mu.Unlock()
		return fmt.Errorf("CAN capture already running")
	}
	c.isRunning = true
	c.mu.Unlock()

	// 创建 SocketCAN 套接字
	sock, err := unix.Socket(unix.AF_CAN, unix.SOCK_RAW, unix.CAN_RAW)
	if err != nil {
		c.isRunning = false
		return fmt.Errorf("failed to create CAN socket: %w", err)
	}
	c.Socket = sock

	// 获取接口索引
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		unix.Close(sock)
		c.isRunning = false
		return fmt.Errorf("failed to find interface %s: %w", c.Interface, err)
	}

	// 绑定到 CAN 接口
	addr := &unix.SockaddrCAN{Ifindex: iface.Index}
	if err := unix.Bind(sock, addr); err != nil {
		unix.Close(sock)
		c.isRunning = false
		return fmt.Errorf("failed to bind to interface: %w", err)
	}

	logger.GetLogger().Infof("CAN capture started on interface %s", c.Interface)

	// 启动数据包接收
	go c.captureFrames(ctx)

	return nil
}

// captureFrames 捕获 CAN 帧
func (c *CANCapture) captureFrames(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.isRunning = false
		c.mu.Unlock()
		if c.Socket >= 0 {
			unix.Close(c.Socket)
		}
		close(c.PacketChan)
	}()

	buf := make([]byte, 16) // CAN 帧大小

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("CAN capture stopped by context")
			return
		case <-c.StopChan:
			logger.GetLogger().Info("CAN capture stopped by signal")
			return
		default:
			// 设置读取超时
			tv := unix.Timeval{Sec: 1, Usec: 0}
			if err := unix.SetsockoptTimeval(c.Socket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
				logger.GetLogger().Errorf("Failed to set socket timeout: %v", err)
				continue
			}

			n, _, err := unix.Recvfrom(c.Socket, buf, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					continue
				}
				logger.GetLogger().Errorf("Failed to receive CAN frame: %v", err)
				continue
			}

			if n >= 16 {
				c.processFrame(buf[:n])
			}
		}
	}
}

// processFrame 处理 CAN 帧
func (c *CANCapture) processFrame(data []byte) {
	c.PacketCount++

	// 解析 CAN 帧
	canID := binary.LittleEndian.Uint32(data[0:4])
	dlc := data[4]
	frameData := data[8:16]

	// 构造数据包模型
	pkt := &models.Packet{
		SessionID: c.SessionID,
		Timestamp: time.Now(),
		Protocol:  "CAN",
		SrcAddr:   fmt.Sprintf("CAN:0x%X", canID),
		DstAddr:   "Broadcast",
		Length:    int(dlc),
		Payload:   frameData[:dlc],
		AnalysisResult: models.JSON{
			"can_id": canID,
			"dlc":    dlc,
		},
	}

	// 发送到处理通道
	select {
	case c.PacketChan <- pkt:
	default:
		logger.GetLogger().Warn("CAN packet channel full, dropping frame")
	}
}

// Stop 停止 CAN 采集
func (c *CANCapture) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return fmt.Errorf("CAN capture not running")
	}

	close(c.StopChan)
	logger.GetLogger().Info("CAN capture stop signal sent")
	return nil
}

// IsRunning 检查是否正在运行
func (c *CANCapture) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isRunning
}

// SendFrame 发送 CAN 帧
func (c *CANCapture) SendFrame(canID uint32, data []byte) error {
	if c.Socket < 0 {
		return fmt.Errorf("CAN socket not initialized")
	}

	if len(data) > 8 {
		return fmt.Errorf("CAN data length exceeds 8 bytes")
	}

	// 构造 CAN 帧
	frame := make([]byte, 16)
	binary.LittleEndian.PutUint32(frame[0:4], canID)
	frame[4] = uint8(len(data))
	copy(frame[8:], data)

	// 发送帧
	if err := unix.Send(c.Socket, frame, 0); err != nil {
		return fmt.Errorf("failed to send CAN frame: %w", err)
	}

	logger.GetLogger().Debugf("Sent CAN frame: ID=0x%X, Data=%v", canID, data)
	return nil
}

// SetupCANInterface 配置 CAN 接口 (需要 root 权限)
func SetupCANInterface(iface string, bitrate int) error {
	// 使用 ip link 命令配置 CAN 接口
	// 实际部署时可以使用 exec.Command 调用系统命令
	// 这里仅提供接口定义
	logger.GetLogger().Infof("Setting up CAN interface %s with bitrate %d", iface, bitrate)

	// 示例命令：
	// ip link set can0 type can bitrate 500000
	// ip link set can0 up

	return nil
}
