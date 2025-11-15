package analyzer

import (
	"fmt"
	"netsecanalyzer/internal/models"
)

// HTTPSParser HTTPS/TLS 协议解析器
type HTTPSParser struct{}

func (p *HTTPSParser) GetName() string {
	return "HTTPS"
}

func (p *HTTPSParser) Parse(packet *models.Packet) (*ProtocolInfo, error) {
	// 检查是否是HTTPS端口
	if packet.SrcPort != 443 && packet.DstPort != 443 {
		return nil, fmt.Errorf("not HTTPS port")
	}

	if len(packet.Payload) < 5 {
		return nil, fmt.Errorf("payload too short for TLS")
	}

	info := &ProtocolInfo{
		Protocol: "HTTPS",
		Fields:   make(map[string]interface{}),
	}

	// TLS记录头解析：类型(1) + 版本(2) + 长度(2)
	recordType := packet.Payload[0]
	version := (uint16(packet.Payload[1]) << 8) | uint16(packet.Payload[2])
	length := (uint16(packet.Payload[3]) << 8) | uint16(packet.Payload[4])

	// 验证TLS记录类型
	recordTypeName := getTLSRecordTypeName(recordType)
	if recordTypeName == "" {
		return nil, fmt.Errorf("invalid TLS record type")
	}

	// 验证TLS版本
	versionName := getTLSVersionName(version)
	if versionName == "" {
		return nil, fmt.Errorf("invalid TLS version")
	}

	info.Fields["record_type"] = recordType
	info.Fields["record_type_name"] = recordTypeName
	info.Fields["version"] = version
	info.Fields["version_name"] = versionName
	info.Fields["length"] = length

	// 如果是握手消息，进一步解析
	if recordType == 22 && len(packet.Payload) >= 6 { // 握手记录
		handshakeType := packet.Payload[5]
		handshakeTypeName := getTLSHandshakeTypeName(handshakeType)

		info.Fields["handshake_type"] = handshakeType
		info.Fields["handshake_type_name"] = handshakeTypeName

		info.Summary = fmt.Sprintf("TLS %s - %s", versionName, handshakeTypeName)
	} else {
		info.Summary = fmt.Sprintf("TLS %s - %s", versionName, recordTypeName)
	}

	return info, nil
}

// getTLSRecordTypeName 获取TLS记录类型名称
func getTLSRecordTypeName(recordType byte) string {
	types := map[byte]string{
		20: "Change Cipher Spec",
		21: "Alert",
		22: "Handshake",
		23: "Application Data",
	}
	return types[recordType]
}

// getTLSVersionName 获取TLS版本名称
func getTLSVersionName(version uint16) string {
	versions := map[uint16]string{
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
		0x0300: "SSL 3.0",
	}
	return versions[version]
}

// getTLSHandshakeTypeName 获取TLS握手类型名称
func getTLSHandshakeTypeName(handshakeType byte) string {
	types := map[byte]string{
		1:  "Client Hello",
		2:  "Server Hello",
		11: "Certificate",
		12: "Server Key Exchange",
		13: "Certificate Request",
		14: "Server Hello Done",
		15: "Certificate Verify",
		16: "Client Key Exchange",
		20: "Finished",
	}
	if name, exists := types[handshakeType]; exists {
		return name
	}
	return fmt.Sprintf("Unknown Handshake (0x%02X)", handshakeType)
}
