package analyzer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"netsecanalyzer/internal/models"
	"strings"
)

// HTTPParser HTTP 协议解析器
type HTTPParser struct{}

func (p *HTTPParser) GetName() string {
	return "HTTP"
}

func (p *HTTPParser) Parse(packet *models.Packet) (*ProtocolInfo, error) {
	if len(packet.Payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	payload := string(packet.Payload)

	// 检查是否为 HTTP 请求或响应
	if !strings.HasPrefix(payload, "GET") &&
		!strings.HasPrefix(payload, "POST") &&
		!strings.HasPrefix(payload, "PUT") &&
		!strings.HasPrefix(payload, "DELETE") &&
		!strings.HasPrefix(payload, "HEAD") &&
		!strings.HasPrefix(payload, "OPTIONS") &&
		!strings.HasPrefix(payload, "HTTP/") {
		return nil, fmt.Errorf("not HTTP protocol")
	}

	info := &ProtocolInfo{
		Protocol: "HTTP",
		Headers:  make(map[string]string),
		Fields:   make(map[string]interface{}),
	}

	reader := bufio.NewReader(bytes.NewReader(packet.Payload))

	// 解析第一行
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	firstLine = strings.TrimSpace(firstLine)

	if strings.HasPrefix(firstLine, "HTTP/") {
		// HTTP 响应
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			info.Version = parts[0]
			fmt.Sscanf(parts[1], "%d", &info.StatusCode)
			if len(parts) >= 3 {
				info.Fields["status_text"] = parts[2]
			}
		}
		info.Summary = fmt.Sprintf("HTTP Response: %d", info.StatusCode)
	} else {
		// HTTP 请求
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 3 {
			info.Method = parts[0]
			info.URI = parts[1]
			info.Version = parts[2]
		}
		info.Summary = fmt.Sprintf("HTTP Request: %s %s", info.Method, info.URI)
	}

	// 解析头部
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF || line == "\r\n" || line == "\n" {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			info.Headers[key] = value
		}
	}

	// 读取剩余内容作为 body
	body, _ := io.ReadAll(reader)
	if len(body) > 0 {
		// 限制 body 大小
		maxBodySize := 1024
		if len(body) > maxBodySize {
			info.Body = string(body[:maxBodySize]) + "..."
		} else {
			info.Body = string(body)
		}
	}

	return info, nil
}
