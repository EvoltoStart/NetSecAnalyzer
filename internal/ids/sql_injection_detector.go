package ids

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// SQLInjectionDetector SQL 注入检测器
type SQLInjectionDetector struct {
	sensitivity int
	patterns    []*regexp.Regexp
}

// NewSQLInjectionDetector 创建 SQL 注入检测器
func NewSQLInjectionDetector(sensitivity int) *SQLInjectionDetector {
	detector := &SQLInjectionDetector{
		sensitivity: sensitivity,
		patterns:    make([]*regexp.Regexp, 0),
	}

	// 编译 SQL 注入特征模式
	detector.compilePatterns()

	return detector
}

// compilePatterns 编译检测模式
func (d *SQLInjectionDetector) compilePatterns() {
	// SQL 注入常见模式
	patterns := []string{
		`(?i)(union\s+select)`,
		`(?i)(select\s+.*\s+from)`,
		`(?i)(insert\s+into)`,
		`(?i)(delete\s+from)`,
		`(?i)(drop\s+table)`,
		`(?i)(update\s+.*\s+set)`,
		`(?i)(exec\s*\()`,
		`(?i)(execute\s*\()`,
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(and\s+1\s*=\s*1)`,
		`(?i)('\s+or\s+'1'\s*=\s*'1)`,
		`(?i)(--\s*$)`,
		`(?i)(;\s*drop)`,
		`(?i)(xp_cmdshell)`,
		`(?i)(benchmark\s*\()`,
		`(?i)(sleep\s*\()`,
		`(?i)(waitfor\s+delay)`,
	}

	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			d.patterns = append(d.patterns, re)
		}
	}
}

// Detect 检测 SQL 注入
func (d *SQLInjectionDetector) Detect(info *PacketInfo) *Alert {
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

	// 检测 SQL 注入特征（同时检测原始和解码后的 payload）
	matches := d.detectSQLInjection(info.Payload)
	decodedMatches := d.detectSQLInjection(decodedPayload)

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
	// 敏感度越高，匹配到一个模式就告警
	if d.sensitivity >= 5 || len(finalMatches) > 1 {
		// 检查是否为 URL 编码攻击
		isEncoded := strings.Contains(info.Payload, "%") && info.Payload != decodedPayload
		description := fmt.Sprintf("Detected SQL injection attempt (%d patterns matched)", len(finalMatches))
		if isEncoded {
			description += " [URL-encoded]"
		}

		return &Alert{
			Type:        "sql_injection",
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

// detectSQLInjection 检测 SQL 注入特征
func (d *SQLInjectionDetector) detectSQLInjection(payload string) []string {
	matches := make([]string, 0)

	for _, pattern := range d.patterns {
		if pattern.MatchString(payload) {
			matches = append(matches, pattern.String())
		}
	}

	return matches
}

// GetName 获取检测器名称
func (d *SQLInjectionDetector) GetName() string {
	return "SQLInjectionDetector"
}
