package ids

// HTTP 流量检测工具函数

// IsHTTPTraffic 判断是否为 HTTP 流量（通过内容判断，不依赖端口）
func IsHTTPTraffic(payload string) bool {
	if len(payload) == 0 {
		return false
	}

	// 检查是否包含 HTTP 请求方法
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, method := range httpMethods {
		if len(payload) >= len(method) && payload[:len(method)] == method {
			return true
		}
	}

	// 检查是否包含 HTTP 响应特征
	if len(payload) >= 5 && payload[:5] == "HTTP/" {
		return true
	}

	// 检查是否包含常见的 HTTP 头部字段（不区分大小写）
	payloadLower := ToLowerSimple(payload)
	httpHeaders := []string{"host:", "user-agent:", "content-type:", "accept:", "cookie:", "referer:"}
	for _, header := range httpHeaders {
		if ContainsSimple(payloadLower, header) {
			return true
		}
	}

	return false
}

// ContainsSimple 简单的字符串包含检查
func ContainsSimple(s, substr string) bool {
	return len(s) >= len(substr) && IndexSimple(s, substr) >= 0
}

// IndexSimple 查找子串位置
func IndexSimple(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(s) < len(substr) {
		return -1
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// ToLowerSimple 转换为小写（简化版本，避免使用 strings 包）
func ToLowerSimple(s string) string {
	if len(s) == 0 {
		return s
	}

	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			result[i] = s[i] + 32
		} else {
			result[i] = s[i]
		}
	}
	return string(result)
}

// GetPayloadPreview 获取 payload 预览（限制长度）
func GetPayloadPreview(payload string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 200
	}
	if len(payload) > maxLen {
		return payload[:maxLen] + "..."
	}
	return payload
}

// GetSeverityByMatchCount 根据匹配数量确定严重程度
func GetSeverityByMatchCount(matchCount int) string {
	if matchCount >= 5 {
		return "critical"
	} else if matchCount >= 3 {
		return "high"
	} else if matchCount >= 2 {
		return "medium"
	}
	return "low"
}
