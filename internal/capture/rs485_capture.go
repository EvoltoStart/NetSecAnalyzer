package capture

import (
	"context"
	"encoding/hex"
	"fmt"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"

	"github.com/goburrow/modbus"
	"github.com/tarm/serial"
)

// RS485Capture RS-485 串口数据采集
type RS485Capture struct {
	PortName    string
	BaudRate    int
	DataBits    int
	Parity      serial.Parity
	StopBits    serial.StopBits
	Port        *serial.Port
	ModbusRTU   modbus.Client
	PacketChan  chan *models.Packet
	StopChan    chan struct{}
	mu          sync.Mutex
	isRunning   bool
	SessionID   uint
	PacketCount int64
}

// NewRS485Capture 创建 RS485 采集实例
func NewRS485Capture(portName string, baudRate, dataBits int, parity string, stopBits int, sessionID uint) (*RS485Capture, error) {
	var parityMode serial.Parity
	switch parity {
	case "N":
		parityMode = serial.ParityNone
	case "E":
		parityMode = serial.ParityEven
	case "O":
		parityMode = serial.ParityOdd
	default:
		parityMode = serial.ParityNone
	}

	var stopBitsMode serial.StopBits
	switch stopBits {
	case 1:
		stopBitsMode = serial.Stop1
	case 2:
		stopBitsMode = serial.Stop2
	default:
		stopBitsMode = serial.Stop1
	}

	return &RS485Capture{
		PortName:   portName,
		BaudRate:   baudRate,
		DataBits:   dataBits,
		Parity:     parityMode,
		StopBits:   stopBitsMode,
		PacketChan: make(chan *models.Packet, 1000),
		StopChan:   make(chan struct{}),
		SessionID:  sessionID,
	}, nil
}

// Start 启动 RS485 数据采集
func (c *RS485Capture) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.isRunning {
		c.mu.Unlock()
		return fmt.Errorf("RS485 capture already running")
	}
	c.isRunning = true
	c.mu.Unlock()

	// 打开串口
	config := &serial.Config{
		Name:        c.PortName,
		Baud:        c.BaudRate,
		Size:        byte(c.DataBits),
		Parity:      c.Parity,
		StopBits:    c.StopBits,
		ReadTimeout: time.Second,
	}

	port, err := serial.OpenPort(config)
	if err != nil {
		c.isRunning = false
		return fmt.Errorf("failed to open serial port %s: %w", c.PortName, err)
	}
	c.Port = port

	logger.GetLogger().Infof("RS485 capture started on port %s", c.PortName)

	// 启动数据接收
	go c.captureData(ctx)

	return nil
}

// captureData 捕获串口数据
func (c *RS485Capture) captureData(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.isRunning = false
		c.mu.Unlock()
		if c.Port != nil {
			c.Port.Close()
		}
		close(c.PacketChan)
	}()

	buf := make([]byte, 256)

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("RS485 capture stopped by context")
			return
		case <-c.StopChan:
			logger.GetLogger().Info("RS485 capture stopped by signal")
			return
		default:
			n, err := c.Port.Read(buf)
			if err != nil {
				if err.Error() == "EOF" {
					continue
				}
				logger.GetLogger().Errorf("Failed to read from serial port: %v", err)
				time.Sleep(time.Millisecond * 100)
				continue
			}

			if n > 0 {
				c.processData(buf[:n])
			}
		}
	}
}

// processData 处理串口数据
func (c *RS485Capture) processData(data []byte) {
	c.PacketCount++

	pkt := &models.Packet{
		SessionID: c.SessionID,
		Timestamp: time.Now(),
		Protocol:  "RS485",
		SrcAddr:   c.PortName,
		DstAddr:   "Device",
		Length:    len(data),
		Payload:   data,
		AnalysisResult: models.JSON{
			"hex": hex.EncodeToString(data),
		},
	}

	// 尝试解析 Modbus 协议
	if len(data) >= 4 {
		pkt.AnalysisResult["slave_id"] = data[0]
		pkt.AnalysisResult["function_code"] = data[1]
	}

	// 发送到处理通道
	select {
	case c.PacketChan <- pkt:
	default:
		logger.GetLogger().Warn("RS485 packet channel full, dropping data")
	}
}

// Stop 停止 RS485 采集
func (c *RS485Capture) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return fmt.Errorf("RS485 capture not running")
	}

	close(c.StopChan)
	logger.GetLogger().Info("RS485 capture stop signal sent")
	return nil
}

// IsRunning 检查是否正在运行
func (c *RS485Capture) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isRunning
}

// InitModbusRTU 初始化 Modbus RTU 客户端
func (c *RS485Capture) InitModbusRTU(slaveID byte) error {
	handler := modbus.NewRTUClientHandler(c.PortName)
	handler.BaudRate = c.BaudRate
	handler.DataBits = c.DataBits
	handler.StopBits = c.DataBits
	handler.SlaveId = slaveID
	handler.Timeout = 1 * time.Second

	if err := handler.Connect(); err != nil {
		return fmt.Errorf("failed to connect Modbus RTU: %w", err)
	}

	c.ModbusRTU = modbus.NewClient(handler)
	logger.GetLogger().Infof("Modbus RTU client initialized for slave %d", slaveID)
	return nil
}

// ReadModbusHoldingRegisters 读取 Modbus 保持寄存器
func (c *RS485Capture) ReadModbusHoldingRegisters(address, quantity uint16) ([]byte, error) {
	if c.ModbusRTU == nil {
		return nil, fmt.Errorf("Modbus RTU client not initialized")
	}

	results, err := c.ModbusRTU.ReadHoldingRegisters(address, quantity)
	if err != nil {
		return nil, fmt.Errorf("failed to read holding registers: %w", err)
	}

	logger.GetLogger().Debugf("Read Modbus holding registers: address=%d, quantity=%d, data=%v",
		address, quantity, results)
	return results, nil
}

// WriteModbusSingleRegister 写入 Modbus 单个寄存器
func (c *RS485Capture) WriteModbusSingleRegister(address, value uint16) error {
	if c.ModbusRTU == nil {
		return fmt.Errorf("Modbus RTU client not initialized")
	}

	_, err := c.ModbusRTU.WriteSingleRegister(address, value)
	if err != nil {
		return fmt.Errorf("failed to write single register: %w", err)
	}

	logger.GetLogger().Debugf("Write Modbus single register: address=%d, value=%d", address, value)
	return nil
}

// ReadModbusCoils 读取 Modbus 线圈
func (c *RS485Capture) ReadModbusCoils(address, quantity uint16) ([]byte, error) {
	if c.ModbusRTU == nil {
		return nil, fmt.Errorf("Modbus RTU client not initialized")
	}

	results, err := c.ModbusRTU.ReadCoils(address, quantity)
	if err != nil {
		return nil, fmt.Errorf("failed to read coils: %w", err)
	}

	return results, nil
}

// WriteModbusSingleCoil 写入 Modbus 单个线圈
func (c *RS485Capture) WriteModbusSingleCoil(address, value uint16) error {
	if c.ModbusRTU == nil {
		return fmt.Errorf("Modbus RTU client not initialized")
	}

	_, err := c.ModbusRTU.WriteSingleCoil(address, value)
	if err != nil {
		return fmt.Errorf("failed to write single coil: %w", err)
	}

	return nil
}

// SendRawData 发送原始数据
func (c *RS485Capture) SendRawData(data []byte) (int, error) {
	if c.Port == nil {
		return 0, fmt.Errorf("serial port not initialized")
	}

	n, err := c.Port.Write(data)
	if err != nil {
		return 0, fmt.Errorf("failed to write to serial port: %w", err)
	}

	logger.GetLogger().Debugf("Sent raw data: %s", hex.EncodeToString(data))
	return n, nil
}
