package ids

import (
	"fmt"
	"regexp"
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
	// 只检测 HTTP 流量
	if info.DstPort != 80 && info.DstPort != 443 && info.DstPort != 8080 {
		return nil
	}

	// 检查 payload
	if len(info.Payload) == 0 {
		return nil
	}

	// 检测 XSS 特征
	matches := d.detectXSS(info.Payload)
	if len(matches) == 0 {
		return nil
	}

	// 根据敏感度决定是否触发告警
	if d.sensitivity >= 5 || len(matches) > 1 {
		return &Alert{
			Type:        "xss",
			Severity:    d.getSeverity(len(matches)),
			Description: fmt.Sprintf("Detected XSS attack attempt (%d patterns matched)", len(matches)),
			Source:      info.SrcIP,
			Destination: info.DstIP,
			Timestamp:   info.Timestamp,
			Details: map[string]interface{}{
				"patterns_matched": matches,
				"target_port":      info.DstPort,
				"payload_preview":  d.getPayloadPreview(info.Payload),
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

// getPayloadPreview 获取 payload 预览
func (d *XSSDetector) getPayloadPreview(payload string) string {
	maxLen := 200
	if len(payload) > maxLen {
		return payload[:maxLen] + "..."
	}
	return payload
}

// getSeverity 根据匹配数量确定严重程度
func (d *XSSDetector) getSeverity(matchCount int) string {
	if matchCount >= 5 {
		return "critical"
	} else if matchCount >= 3 {
		return "high"
	} else if matchCount >= 2 {
		return "medium"
	}
	return "low"
}

// GetName 获取检测器名称
func (d *XSSDetector) GetName() string {
	return "XSSDetector"
}
