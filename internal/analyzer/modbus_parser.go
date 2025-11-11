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

	info := &ProtocolInfo{
		Protocol: "Modbus",
		Fields:   make(map[string]interface{}),
	}

	// Modbus TCP/RTU 通用格式
	// [Transaction ID (2)] [Protocol ID (2)] [Length (2)] [Unit ID (1)] [Function Code (1)] [Data (N)]

	// 如果是 Modbus TCP
	if len(packet.Payload) >= 7 {
		transactionID := (uint16(packet.Payload[0]) << 8) | uint16(packet.Payload[1])
		protocolID := (uint16(packet.Payload[2]) << 8) | uint16(packet.Payload[3])
		length := (uint16(packet.Payload[4]) << 8) | uint16(packet.Payload[5])
		unitID := packet.Payload[6]
		functionCode := packet.Payload[7]

		if protocolID == 0 { // Modbus TCP 协议标识符为 0
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

	// Modbus RTU 格式
	if len(packet.Payload) >= 2 {
		unitID := packet.Payload[0]
		functionCode := packet.Payload[1]

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

	return nil, fmt.Errorf("invalid Modbus packet")
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
