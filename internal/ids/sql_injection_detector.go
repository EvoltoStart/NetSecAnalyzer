package ids

import (
	"fmt"
	"regexp"
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
	// 只检测 HTTP 流量
	if info.DstPort != 80 && info.DstPort != 443 && info.DstPort != 8080 {
		return nil
	}

	// 检查 payload
	if len(info.Payload) == 0 {
		return nil
	}

	// 检测 SQL 注入特征
	matches := d.detectSQLInjection(info.Payload)
	if len(matches) == 0 {
		return nil
	}

	// 根据敏感度决定是否触发告警
	// 敏感度越高，匹配到一个模式就告警
	if d.sensitivity >= 5 || len(matches) > 1 {
		return &Alert{
			Type:        "sql_injection",
			Severity:    d.getSeverity(len(matches)),
			Description: fmt.Sprintf("Detected SQL injection attempt (%d patterns matched)", len(matches)),
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

// getPayloadPreview 获取 payload 预览
func (d *SQLInjectionDetector) getPayloadPreview(payload string) string {
	maxLen := 200
	if len(payload) > maxLen {
		return payload[:maxLen] + "..."
	}
	return payload
}

// getSeverity 根据匹配数量确定严重程度
func (d *SQLInjectionDetector) getSeverity(matchCount int) string {
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
func (d *SQLInjectionDetector) GetName() string {
	return "SQLInjectionDetector"
}
