package analyzer

import (
	"fmt"
	"netsecanalyzer/internal/models"
)

// DNSParser DNS 协议解析器
type DNSParser struct{}

func (p *DNSParser) GetName() string {
	return "DNS"
}

func (p *DNSParser) Parse(packet *models.Packet) (*ProtocolInfo, error) {
	if len(packet.Payload) < 12 {
		return nil, fmt.Errorf("payload too short for DNS")
	}

	if packet.DstPort != 53 && packet.SrcPort != 53 {
		return nil, fmt.Errorf("not DNS port")
	}

	info := &ProtocolInfo{
		Protocol: "DNS",
		Fields:   make(map[string]interface{}),
	}

	payload := packet.Payload

	// DNS 头部
	transactionID := (uint16(payload[0]) << 8) | uint16(payload[1])
	flags := (uint16(payload[2]) << 8) | uint16(payload[3])
	qdCount := (uint16(payload[4]) << 8) | uint16(payload[5])
	anCount := (uint16(payload[6]) << 8) | uint16(payload[7])
	nsCount := (uint16(payload[8]) << 8) | uint16(payload[9])
	arCount := (uint16(payload[10]) << 8) | uint16(payload[11])

	isResponse := (flags & 0x8000) != 0
	opcode := (flags >> 11) & 0x0F
	rcode := flags & 0x000F

	info.Fields["transaction_id"] = transactionID
	info.Fields["is_response"] = isResponse
	info.Fields["opcode"] = opcode
	info.Fields["rcode"] = rcode
	info.Fields["questions"] = qdCount
	info.Fields["answers"] = anCount
	info.Fields["authority"] = nsCount
	info.Fields["additional"] = arCount

	if isResponse {
		info.Summary = fmt.Sprintf("DNS Response: ID=%d, Answers=%d", transactionID, anCount)
		info.Fields["response_code"] = getDNSResponseCode(byte(rcode))
	} else {
		info.Summary = fmt.Sprintf("DNS Query: ID=%d, Questions=%d", transactionID, qdCount)
	}

	// 解析查询名称（简化版本）
	if len(payload) > 12 && qdCount > 0 {
		domainName, _ := parseDNSName(payload[12:])
		info.Fields["query_name"] = domainName
	}

	return info, nil
}

func parseDNSName(data []byte) (string, int) {
	var name string
	pos := 0

	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}

		// 处理压缩指针
		if length >= 0xC0 {
			pos += 2
			break
		}

		pos++
		if pos+length > len(data) {
			break
		}

		if name != "" {
			name += "."
		}
		name += string(data[pos : pos+length])
		pos += length
	}

	return name, pos
}

func getDNSResponseCode(rcode byte) string {
	codes := map[byte]string{
		0: "No Error",
		1: "Format Error",
		2: "Server Failure",
		3: "Name Error",
		4: "Not Implemented",
		5: "Refused",
	}

	if name, exists := codes[rcode]; exists {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", rcode)
}
