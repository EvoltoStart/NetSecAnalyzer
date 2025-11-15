package analyzer

import (
	"fmt"
	"netsecanalyzer/internal/models"
)

// ModbusParser Modbus 协议解析器
type ModbusParser struct{}

func (p *ModbusParser) GetName() string {
	return "Modbus"
}

func (p *ModbusParser) Parse(packet *models.Packet) (*ProtocolInfo, error) {
	if len(packet.Payload) < 2 {
		return nil, fmt.Errorf("payload too short for Modbus")
	}

	// 严格检查：只有端口502或明确的Modbus特征才尝试解析
	isModbusPort := packet.SrcPort == 502 || packet.DstPort == 502

	// 如果不是Modbus端口，进行更严格的检查
	if !isModbusPort {
		// 检查是否有明显的非Modbus特征
		if isHTTPSTraffic(packet) || isDNSTraffic(packet) || isOtherKnownProtocol(packet) {
			return nil, fmt.Errorf("not Modbus protocol")
		}
	}

	info := &ProtocolInfo{
		Protocol: "Modbus",
		Fields:   make(map[string]interface{}),
	}

	// Modbus TCP/RTU 通用格式
	// [Transaction ID (2)] [Protocol ID (2)] [Length (2)] [Unit ID (1)] [Function Code (1)] [Data (N)]

	// 如果是 Modbus TCP
	if len(packet.Payload) >= 8 { // 至少需要8字节才是完整的Modbus TCP
		transactionID := (uint16(packet.Payload[0]) << 8) | uint16(packet.Payload[1])
		protocolID := (uint16(packet.Payload[2]) << 8) | uint16(packet.Payload[3])
		length := (uint16(packet.Payload[4]) << 8) | uint16(packet.Payload[5])
		unitID := packet.Payload[6]
		functionCode := packet.Payload[7]

		// 严格验证Modbus TCP格式
		if protocolID == 0 && isValidModbusFunctionCode(functionCode) && length > 0 && length < 256 {
			info.Fields["transaction_id"] = transactionID
			info.Fields["protocol_id"] = protocolID
			info.Fields["length"] = length
			info.Fields["unit_id"] = unitID
			info.Fields["function_code"] = functionCode
			info.Fields["function_name"] = getModbusFunctionName(functionCode)

			// 检查异常响应
			if functionCode >= 0x80 {
				info.Fields["exception"] = true
				if len(packet.Payload) > 8 {
					info.Fields["exception_code"] = packet.Payload[8]
					info.Fields["exception_name"] = getModbusExceptionName(packet.Payload[8])
				}
				info.Summary = fmt.Sprintf("Modbus Exception: %s", info.Fields["exception_name"])
			} else {
				info.Summary = fmt.Sprintf("Modbus %s", info.Fields["function_name"])
			}

			return info, nil
		}
	}

	// 只有在明确是Modbus端口时才尝试RTU格式
	if isModbusPort && len(packet.Payload) >= 4 { // RTU至少需要4字节（地址+功能码+数据+CRC）
		unitID := packet.Payload[0]
		functionCode := packet.Payload[1]

		// 验证功能码是否有效
		if !isValidModbusFunctionCode(functionCode) {
			return nil, fmt.Errorf("invalid Modbus function code")
		}

		info.Fields["unit_id"] = unitID
		info.Fields["function_code"] = functionCode
		info.Fields["function_name"] = getModbusFunctionName(functionCode)

		if functionCode >= 0x80 {
			info.Fields["exception"] = true
			if len(packet.Payload) > 2 {
				info.Fields["exception_code"] = packet.Payload[2]
				info.Fields["exception_name"] = getModbusExceptionName(packet.Payload[2])
			}
			info.Summary = fmt.Sprintf("Modbus RTU Exception: %s", info.Fields["exception_name"])
		} else {
			info.Summary = fmt.Sprintf("Modbus RTU %s", info.Fields["function_name"])
		}

		return info, nil
	}

	return nil, fmt.Errorf("not a valid Modbus packet")
}

func getModbusFunctionName(code byte) string {
	functionNames := map[byte]string{
		0x01: "Read Coils",
		0x02: "Read Discrete Inputs",
		0x03: "Read Holding Registers",
		0x04: "Read Input Registers",
		0x05: "Write Single Coil",
		0x06: "Write Single Register",
		0x0F: "Write Multiple Coils",
		0x10: "Write Multiple Registers",
		0x17: "Read/Write Multiple Registers",
	}

	if name, exists := functionNames[code]; exists {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", code)
}

func getModbusExceptionName(code byte) string {
	exceptionNames := map[byte]string{
		0x01: "Illegal Function",
		0x02: "Illegal Data Address",
		0x03: "Illegal Data Value",
		0x04: "Slave Device Failure",
		0x05: "Acknowledge",
		0x06: "Slave Device Busy",
		0x08: "Memory Parity Error",
		0x0A: "Gateway Path Unavailable",
		0x0B: "Gateway Target Device Failed to Respond",
	}

	if name, exists := exceptionNames[code]; exists {
		return name
	}
	return fmt.Sprintf("Unknown Exception (0x%02X)", code)
}

// isValidModbusFunctionCode 检查是否是有效的Modbus功能码
func isValidModbusFunctionCode(code byte) bool {
	// 标准Modbus功能码
	validCodes := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10, 0x17,
		// 异常响应码
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x8F, 0x90, 0x97,
	}

	for _, validCode := range validCodes {
		if code == validCode {
			return true
		}
	}

	// 允许一些扩展功能码范围
	return (code >= 0x01 && code <= 0x7F) || (code >= 0x81 && code <= 0xFF)
}

// isHTTPSTraffic 检查是否是HTTPS流量
func isHTTPSTraffic(packet *models.Packet) bool {
	if packet.SrcPort == 443 || packet.DstPort == 443 {
		// 检查TLS握手特征
		if len(packet.Payload) >= 5 {
			// TLS记录头：类型(1) + 版本(2) + 长度(2)
			recordType := packet.Payload[0]
			version := (uint16(packet.Payload[1]) << 8) | uint16(packet.Payload[2])

			// TLS记录类型：握手(22), 应用数据(23), 警告(21), 密码变更(20)
			if recordType >= 20 && recordType <= 23 {
				// TLS版本检查：1.0(0x0301), 1.1(0x0302), 1.2(0x0303), 1.3(0x0304)
				if version >= 0x0301 && version <= 0x0304 {
					return true
				}
			}
		}
		return true // 443端口默认认为是HTTPS
	}
	return false
}

// isDNSTraffic 检查是否是DNS流量
func isDNSTraffic(packet *models.Packet) bool {
	if packet.SrcPort == 53 || packet.DstPort == 53 {
		return true
	}

	// 检查mDNS (5353端口)
	if packet.SrcPort == 5353 || packet.DstPort == 5353 {
		return true
	}

	return false
}

// isOtherKnownProtocol 检查是否是其他已知协议
func isOtherKnownProtocol(packet *models.Packet) bool {
	knownPorts := map[int]bool{
		80:   true, // HTTP
		443:  true, // HTTPS
		53:   true, // DNS
		21:   true, // FTP
		22:   true, // SSH
		23:   true, // Telnet
		25:   true, // SMTP
		110:  true, // POP3
		143:  true, // IMAP
		993:  true, // IMAPS
		995:  true, // POP3S
		587:  true, // SMTP submission
		5353: true, // mDNS
		67:   true, // DHCP server
		68:   true, // DHCP client
	}

	return knownPorts[packet.SrcPort] || knownPorts[packet.DstPort]
}
