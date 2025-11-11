package analyzer

import (
	"fmt"
	"netsecanalyzer/internal/models"
	"strings"
)

// FTPParser FTP 协议解析器
type FTPParser struct{}

func (p *FTPParser) GetName() string {
	return "FTP"
}

func (p *FTPParser) Parse(packet *models.Packet) (*ProtocolInfo, error) {
	if len(packet.Payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	if packet.DstPort != 21 && packet.SrcPort != 21 {
		return nil, fmt.Errorf("not FTP control port")
	}

	payload := strings.TrimSpace(string(packet.Payload))
	if payload == "" {
		return nil, fmt.Errorf("empty FTP payload")
	}

	info := &ProtocolInfo{
		Protocol: "FTP",
		Fields:   make(map[string]interface{}),
	}

	// FTP 响应以数字开头
	if payload[0] >= '0' && payload[0] <= '9' {
		parts := strings.SplitN(payload, " ", 2)
		var code int
		fmt.Sscanf(parts[0], "%d", &code)
		info.StatusCode = code
		info.Fields["response_code"] = code

		if len(parts) > 1 {
			info.Fields["message"] = parts[1]
			info.Summary = fmt.Sprintf("FTP Response: %d %s", code, parts[1])
		} else {
			info.Summary = fmt.Sprintf("FTP Response: %d", code)
		}
	} else {
		// FTP 命令
		parts := strings.SplitN(payload, " ", 2)
		command := strings.ToUpper(parts[0])
		info.Method = command

		if len(parts) > 1 {
			// 隐藏密码
			if command == "PASS" {
				info.Fields["argument"] = "***"
			} else {
				info.Fields["argument"] = parts[1]
			}
			info.Summary = fmt.Sprintf("FTP Command: %s", command)
		} else {
			info.Summary = fmt.Sprintf("FTP Command: %s", command)
		}
	}

	return info, nil
}
