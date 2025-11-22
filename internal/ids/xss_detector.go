package ids

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// XSSDetector XSS 攻击检测器
type XSSDetector struct {
	sensitivity int
	patterns    []*regexp.Regexp
}

// NewXSSDetector 创建 XSS 检测器
func NewXSSDetector(sensitivity int) *XSSDetector {
	detector := &XSSDetector{
		sensitivity: sensitivity,
		patterns:    make([]*regexp.Regexp, 0),
	}

	// 编译 XSS 特征模式
	detector.compilePatterns()

	return detector
}

// compilePatterns 编译检测模式
func (d *XSSDetector) compilePatterns() {
	// XSS 常见模式
	patterns := []string{
		`(?i)(<script[^>]*>)`,
		`(?i)(</script>)`,
		`(?i)(javascript:)`,
		`(?i)(onerror\s*=)`,
		`(?i)(onload\s*=)`,
		`(?i)(onclick\s*=)`,
		`(?i)(onmouseover\s*=)`,
		`(?i)(<iframe[^>]*>)`,
		`(?i)(<embed[^>]*>)`,
		`(?i)(<object[^>]*>)`,
		`(?i)(eval\s*\()`,
		`(?i)(alert\s*\()`,
		`(?i)(document\.cookie)`,
		`(?i)(document\.write)`,
		`(?i)(<img[^>]*onerror)`,
		`(?i)(<svg[^>]*onload)`,
	}

	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			d.patterns = append(d.patterns, re)
		}
	}
}

// Detect 检测 XSS 攻击
func (d *XSSDetector) Detect(info *PacketInfo) *Alert {
	// 检查 payload 是否存在
	if len(info.Payload) == 0 {
		return nil
	}

	// 判断是否为 HTTP 流量
	if !IsHTTPTraffic(info.Payload) {
		return nil
	}

	// URL 解码 payload（处理 URL 编码的攻击）
	decodedPayload := info.Payload
	if decoded, err := url.QueryUnescape(info.Payload); err == nil {
		decodedPayload = decoded
	}

	// 检测 XSS 特征（同时检测原始和解码后的 payload）
	matches := d.detectXSS(info.Payload)
	decodedMatches := d.detectXSS(decodedPayload)

	// 合并匹配结果
	allMatches := make(map[string]bool)
	for _, m := range matches {
		allMatches[m] = true
	}
	for _, m := range decodedMatches {
		allMatches[m] = true
	}

	// 转换为切片
	finalMatches := make([]string, 0, len(allMatches))
	for m := range allMatches {
		finalMatches = append(finalMatches, m)
	}

	if len(finalMatches) == 0 {
		return nil
	}

	// 根据敏感度决定是否触发告警
	if d.sensitivity >= 5 || len(finalMatches) > 1 {
		// 检查是否为 URL 编码攻击
		isEncoded := strings.Contains(info.Payload, "%") && info.Payload != decodedPayload
		description := fmt.Sprintf("Detected XSS attack attempt (%d patterns matched)", len(finalMatches))
		if isEncoded {
			description += " [URL-encoded]"
		}

		return &Alert{
			Type:        "xss",
			Severity:    GetSeverityByMatchCount(len(finalMatches)),
			Description: description,
			Source:      info.SrcIP,
			Destination: info.DstIP,
			Timestamp:   info.Timestamp,
			Details: map[string]interface{}{
				"patterns_matched": finalMatches,
				"target_port":      info.DstPort,
				"payload_preview":  GetPayloadPreview(info.Payload, 200),
				"is_url_encoded":   isEncoded,
				"decoded_preview":  GetPayloadPreview(decodedPayload, 200),
			},
		}
	}

	return nil
}

// detectXSS 检测 XSS 特征
func (d *XSSDetector) detectXSS(payload string) []string {
	matches := make([]string, 0)

	for _, pattern := range d.patterns {
		if pattern.MatchString(payload) {
			matches = append(matches, pattern.String())
		}
	}

	return matches
}

// GetName 获取检测器名称
func (d *XSSDetector) GetName() string {
	return "XSSDetector"
}
