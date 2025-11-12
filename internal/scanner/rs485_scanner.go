package scanner

import (
	"context"
	"fmt"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"

	"github.com/goburrow/modbus"
)

// RS485Scanner RS-485/Modbus 扫描器
type RS485Scanner struct {
	PortName      string
	BaudRate      int
	DataBits      int
	Parity        string
	StopBits      int
	Timeout       time.Duration
	MaxConcurrent int
	Progress      func(current, total int)
}

// NewRS485Scanner 创建 RS485 扫描器
func NewRS485Scanner(port string, baudRate int, timeout time.Duration, maxConcurrent int) *RS485Scanner {
	return &RS485Scanner{
		PortName:      port,
		BaudRate:      baudRate,
		DataBits:      8,
		Parity:        "N",
		StopBits:      1,
		Timeout:       timeout,
		MaxConcurrent: maxConcurrent,
	}
}

// RS485ScanResult RS-485 扫描结果
type RS485ScanResult struct {
	Port            string             `json:"port"`
	ActiveDevices   []ModbusDeviceInfo `json:"active_devices"`
	TotalDevices    int                `json:"total_devices"`
	ScanDuration    time.Duration      `json:"scan_duration"`
	Vulnerabilities []ModbusVuln       `json:"vulnerabilities"`
}

// ModbusDeviceInfo Modbus 设备信息
type ModbusDeviceInfo struct {
	SlaveID        byte                   `json:"slave_id"`
	ResponseTime   time.Duration          `json:"response_time"`
	SupportedFuncs []byte                 `json:"supported_functions"`
	DeviceInfo     map[string]interface{} `json:"device_info"`
	Fingerprint    string                 `json:"fingerprint"`
	VendorID       string                 `json:"vendor_id,omitempty"`
	ProductCode    string                 `json:"product_code,omitempty"`
	MajorMinorRev  string                 `json:"major_minor_rev,omitempty"`
}

// ModbusVuln Modbus 漏洞
type ModbusVuln struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	SlaveID     byte      `json:"slave_id"`
	Timestamp   time.Time `json:"timestamp"`
	Details     string    `json:"details,omitempty"`
}

// ScanModbusDevices 扫描 Modbus 设备
func (s *RS485Scanner) ScanModbusDevices(ctx context.Context, startAddr, endAddr byte) (*RS485ScanResult, error) {
	startTime := time.Now()

	result := &RS485ScanResult{
		Port:            s.PortName,
		ActiveDevices:   []ModbusDeviceInfo{},
		Vulnerabilities: []ModbusVuln{},
	}

	logger.GetLogger().Infof("Starting Modbus device scan on %s (addresses %d-%d)", s.PortName, startAddr, endAddr)

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.MaxConcurrent)

	totalAddrs := int(endAddr - startAddr + 1)
	scannedCount := 0

	for addr := startAddr; addr <= endAddr; addr++ {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Modbus scan cancelled")
			return result, ctx.Err()
		default:
			wg.Add(1)
			go func(slaveID byte) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				deviceInfo := s.scanSingleDevice(slaveID)
				if deviceInfo != nil {
					mu.Lock()
					result.ActiveDevices = append(result.ActiveDevices, *deviceInfo)

					// 检测漏洞
					vulns := s.detectDeviceVulnerabilities(deviceInfo)
					result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
					mu.Unlock()

					logger.GetLogger().Infof("Found Modbus device at address %d", slaveID)
				}

				mu.Lock()
				scannedCount++
				if s.Progress != nil {
					s.Progress(scannedCount, totalAddrs)
				}
				mu.Unlock()
			}(addr)
		}
	}

	wg.Wait()

	result.TotalDevices = len(result.ActiveDevices)
	result.ScanDuration = time.Since(startTime)

	logger.GetLogger().Infof("Modbus scan completed: %d devices found, %d vulnerabilities detected",
		result.TotalDevices, len(result.Vulnerabilities))

	return result, nil
}

// scanSingleDevice 扫描单个设备
func (s *RS485Scanner) scanSingleDevice(slaveID byte) *ModbusDeviceInfo {
	handler := modbus.NewRTUClientHandler(s.PortName)
	handler.BaudRate = s.BaudRate
	handler.DataBits = s.DataBits
	handler.StopBits = s.StopBits
	handler.SlaveId = slaveID
	handler.Timeout = s.Timeout

	if err := handler.Connect(); err != nil {
		return nil
	}
	defer handler.Close()

	client := modbus.NewClient(handler)

	// 测试设备响应
	startTime := time.Now()
	_, err := client.ReadHoldingRegisters(0, 1)
	responseTime := time.Since(startTime)

	if err != nil {
		// 尝试读取线圈
		_, err = client.ReadCoils(0, 1)
		if err != nil {
			return nil // 设备不响应
		}
	}

	deviceInfo := &ModbusDeviceInfo{
		SlaveID:        slaveID,
		ResponseTime:   responseTime,
		SupportedFuncs: []byte{},
		DeviceInfo:     make(map[string]interface{}),
	}

	// 枚举支持的功能码
	deviceInfo.SupportedFuncs = s.enumerateFunctionCodes(client)

	// 尝试读取设备标识（功能码 0x2B/0x0E）
	s.readDeviceIdentification(client, deviceInfo)

	// 生成设备指纹
	deviceInfo.Fingerprint = s.generateFingerprint(deviceInfo)

	return deviceInfo
}

// enumerateFunctionCodes 枚举支持的功能码
func (s *RS485Scanner) enumerateFunctionCodes(client modbus.Client) []byte {
	var supportedFuncs []byte

	// 常见的 Modbus 功能码
	testFuncs := []struct {
		code byte
		test func() error
	}{
		{0x01, func() error { _, err := client.ReadCoils(0, 1); return err }},
		{0x02, func() error { _, err := client.ReadDiscreteInputs(0, 1); return err }},
		{0x03, func() error { _, err := client.ReadHoldingRegisters(0, 1); return err }},
		{0x04, func() error { _, err := client.ReadInputRegisters(0, 1); return err }},
		{0x05, func() error { _, err := client.WriteSingleCoil(0, 0); return err }},
		{0x06, func() error { _, err := client.WriteSingleRegister(0, 0); return err }},
		{0x0F, func() error { _, err := client.WriteMultipleCoils(0, 1, []byte{0}); return err }},
		{0x10, func() error { _, err := client.WriteMultipleRegisters(0, 1, []byte{0, 0}); return err }},
	}

	for _, tf := range testFuncs {
		err := tf.test()
		if err == nil || !isModbusIllegalFunction(err) {
			supportedFuncs = append(supportedFuncs, tf.code)
		}
	}

	return supportedFuncs
}

// readDeviceIdentification 读取设备标识
func (s *RS485Scanner) readDeviceIdentification(client modbus.Client, deviceInfo *ModbusDeviceInfo) {
	// Modbus 功能码 0x2B/0x0E (Read Device Identification)
	// 这需要自定义实现，这里简化处理

	// 尝试读取常见的设备信息寄存器
	// 不同厂商的设备信息位置不同，这里尝试常见位置

	// 尝试读取寄存器 40001-40010（地址 0-9）
	data, err := client.ReadHoldingRegisters(0, 10)
	if err == nil && len(data) > 0 {
		deviceInfo.DeviceInfo["holding_registers_0_9"] = data
	}

	// 尝试读取输入寄存器 30001-30010（地址 0-9）
	data, err = client.ReadInputRegisters(0, 10)
	if err == nil && len(data) > 0 {
		deviceInfo.DeviceInfo["input_registers_0_9"] = data
	}
}

// generateFingerprint 生成设备指纹
func (s *RS485Scanner) generateFingerprint(deviceInfo *ModbusDeviceInfo) string {
	// 基于响应时间、支持的功能码等生成指纹
	fingerprint := fmt.Sprintf("RT:%dms|FC:%v",
		deviceInfo.ResponseTime.Milliseconds(),
		deviceInfo.SupportedFuncs)

	return fingerprint
}

// detectDeviceVulnerabilities 检测设备漏洞
func (s *RS485Scanner) detectDeviceVulnerabilities(deviceInfo *ModbusDeviceInfo) []ModbusVuln {
	var vulns []ModbusVuln

	// 检查是否支持写操作（潜在的安全风险）
	hasWriteFunc := false
	for _, fc := range deviceInfo.SupportedFuncs {
		if fc == 0x05 || fc == 0x06 || fc == 0x0F || fc == 0x10 {
			hasWriteFunc = true
			break
		}
	}

	if hasWriteFunc {
		vulns = append(vulns, ModbusVuln{
			Type:        "unrestricted_write",
			Severity:    "medium",
			Description: "Device supports write operations without authentication",
			SlaveID:     deviceInfo.SlaveID,
			Timestamp:   time.Now(),
			Details:     "Modbus protocol does not provide built-in authentication",
		})
	}

	// 检查响应时间异常
	if deviceInfo.ResponseTime > 1*time.Second {
		vulns = append(vulns, ModbusVuln{
			Type:        "slow_response",
			Severity:    "info",
			Description: fmt.Sprintf("Device has slow response time: %s", deviceInfo.ResponseTime),
			SlaveID:     deviceInfo.SlaveID,
			Timestamp:   time.Now(),
		})
	}

	// 检查是否支持所有功能码（可能是模拟器或测试设备）
	if len(deviceInfo.SupportedFuncs) >= 8 {
		vulns = append(vulns, ModbusVuln{
			Type:        "full_function_support",
			Severity:    "info",
			Description: "Device supports all common Modbus functions (possible simulator)",
			SlaveID:     deviceInfo.SlaveID,
			Timestamp:   time.Now(),
		})
	}

	return vulns
}

// TestModbusVulnerabilities 测试 Modbus 漏洞
func (s *RS485Scanner) TestModbusVulnerabilities(ctx context.Context, slaveID byte) ([]ModbusVuln, error) {
	var vulns []ModbusVuln

	handler := modbus.NewRTUClientHandler(s.PortName)
	handler.BaudRate = s.BaudRate
	handler.DataBits = s.DataBits
	handler.StopBits = s.StopBits
	handler.SlaveId = slaveID
	handler.Timeout = s.Timeout

	if err := handler.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to device: %w", err)
	}
	defer handler.Close()

	client := modbus.NewClient(handler)

	// 测试 1: 未授权读取
	_, err := client.ReadHoldingRegisters(0, 100)
	if err == nil {
		vulns = append(vulns, ModbusVuln{
			Type:        "unauthorized_read",
			Severity:    "low",
			Description: "Device allows unrestricted read access to holding registers",
			SlaveID:     slaveID,
			Timestamp:   time.Now(),
		})
	}

	// 测试 2: 未授权写入（谨慎测试）
	// 注意：这可能会影响实际设备，仅在测试环境使用
	originalValue, err := client.ReadHoldingRegisters(0, 1)
	if err == nil {
		// 尝试写入相同的值（不改变设备状态）
		_, err = client.WriteSingleRegister(0, uint16(originalValue[0])<<8|uint16(originalValue[1]))
		if err == nil {
			vulns = append(vulns, ModbusVuln{
				Type:        "unauthorized_write",
				Severity:    "high",
				Description: "Device allows unrestricted write access without authentication",
				SlaveID:     slaveID,
				Timestamp:   time.Now(),
				Details:     "Critical: Device can be modified by any client",
			})
		}
	}

	// 测试 3: 异常功能码响应
	// 发送非法功能码，检查设备响应
	// 这需要底层实现，这里简化

	logger.GetLogger().Infof("Vulnerability test completed for device %d: %d issues found", slaveID, len(vulns))
	return vulns, nil
}

// isModbusIllegalFunction 检查是否为非法功能码错误
func isModbusIllegalFunction(err error) bool {
	if err == nil {
		return false
	}
	// Modbus 异常码 0x01 表示非法功能码
	return err.Error() == "modbus: exception '1' (illegal function), function '1'"
}

// ScanModbusMemoryMap 扫描 Modbus 内存映射
func (s *RS485Scanner) ScanModbusMemoryMap(ctx context.Context, slaveID byte) (map[string]interface{}, error) {
	handler := modbus.NewRTUClientHandler(s.PortName)
	handler.BaudRate = s.BaudRate
	handler.DataBits = s.DataBits
	handler.StopBits = s.StopBits
	handler.SlaveId = slaveID
	handler.Timeout = s.Timeout

	if err := handler.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to device: %w", err)
	}
	defer handler.Close()

	client := modbus.NewClient(handler)
	memoryMap := make(map[string]interface{})

	// 扫描保持寄存器（Holding Registers）
	holdingRegs := make(map[uint16][]byte)
	for addr := uint16(0); addr < 100; addr += 10 {
		data, err := client.ReadHoldingRegisters(addr, 10)
		if err == nil {
			holdingRegs[addr] = data
		}
	}
	memoryMap["holding_registers"] = holdingRegs

	// 扫描输入寄存器（Input Registers）
	inputRegs := make(map[uint16][]byte)
	for addr := uint16(0); addr < 100; addr += 10 {
		data, err := client.ReadInputRegisters(addr, 10)
		if err == nil {
			inputRegs[addr] = data
		}
	}
	memoryMap["input_registers"] = inputRegs

	// 扫描线圈（Coils）
	coils := make(map[uint16][]byte)
	for addr := uint16(0); addr < 100; addr += 10 {
		data, err := client.ReadCoils(addr, 10)
		if err == nil {
			coils[addr] = data
		}
	}
	memoryMap["coils"] = coils

	// 扫描离散输入（Discrete Inputs）
	discreteInputs := make(map[uint16][]byte)
	for addr := uint16(0); addr < 100; addr += 10 {
		data, err := client.ReadDiscreteInputs(addr, 10)
		if err == nil {
			discreteInputs[addr] = data
		}
	}
	memoryMap["discrete_inputs"] = discreteInputs

	logger.GetLogger().Infof("Memory map scan completed for device %d", slaveID)
	return memoryMap, nil
}
