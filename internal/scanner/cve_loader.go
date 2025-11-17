package scanner

import (
	"fmt"
	"netsecanalyzer/pkg/logger"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// CVERule CVE 规则
type CVERule struct {
	ServicePattern  string  `yaml:"service_pattern"`
	VersionPattern  string  `yaml:"version_pattern"` // 保留用于简单匹配
	VersionMin      string  `yaml:"version_min"`     // 最小版本（包含）
	VersionMax      string  `yaml:"version_max"`     // 最大版本（包含）
	CVEID           string  `yaml:"cve_id"`
	CVSS            float64 `yaml:"cvss"`
	Severity        string  `yaml:"severity"`
	Title           string  `yaml:"title"`
	Description     string  `yaml:"description"`
	Solution        string  `yaml:"solution"`
	AffectedVersion string  `yaml:"affected_version"`
	Enabled         bool    `yaml:"enabled"`
}

// CVERuleSet CVE 规则集
type CVERuleSet struct {
	Service string    `yaml:"service"`
	Rules   []CVERule `yaml:"rules"`
}

// CVELoader CVE 规则加载器
type CVELoader struct {
	rulesDir string
	rules    []CVERule
}

// NewCVELoader 创建 CVE 规则加载器
func NewCVELoader(rulesDir string) *CVELoader {
	return &CVELoader{
		rulesDir: rulesDir,
		rules:    make([]CVERule, 0),
	}
}

// LoadRules 加载所有 CVE 规则
func (l *CVELoader) LoadRules() error {
	// 检查目录是否存在
	if _, err := os.Stat(l.rulesDir); os.IsNotExist(err) {
		logger.GetLogger().Warnf("CVE rules directory not found: %s, using default rules", l.rulesDir)
		l.rules = getDefaultCVERules()
		return nil
	}

	// 读取目录中的所有 YAML 文件
	files, err := os.ReadDir(l.rulesDir)
	if err != nil {
		logger.GetLogger().Errorf("Failed to read CVE rules directory: %v", err)
		l.rules = getDefaultCVERules()
		return err
	}

	loadedCount := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// 只处理 .yaml 和 .yml 文件
		if !strings.HasSuffix(file.Name(), ".yaml") && !strings.HasSuffix(file.Name(), ".yml") {
			continue
		}

		filePath := filepath.Join(l.rulesDir, file.Name())
		if err := l.loadRuleFile(filePath); err != nil {
			logger.GetLogger().Errorf("Failed to load CVE rule file %s: %v", filePath, err)
			continue
		}
		loadedCount++
	}

	if loadedCount == 0 {
		logger.GetLogger().Warn("No CVE rule files loaded, using default rules")
		l.rules = getDefaultCVERules()
	} else {
		logger.GetLogger().Infof("Loaded %d CVE rules from %d files", len(l.rules), loadedCount)
	}

	return nil
}

// loadRuleFile 加载单个规则文件
func (l *CVELoader) loadRuleFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var ruleSet CVERuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// 添加规则（默认启用所有规则）
	for _, rule := range ruleSet.Rules {
		// 如果规则有 CVE ID，默认启用
		if rule.CVEID != "" && !rule.Enabled {
			rule.Enabled = true
		}
		// 只添加启用的规则
		if rule.Enabled {
			l.rules = append(l.rules, rule)
		}
	}

	return nil
}

// GetRules 获取所有规则
func (l *CVELoader) GetRules() []CVERule {
	return l.rules
}

// GetEnabledRules 获取启用的规则
func (l *CVELoader) GetEnabledRules() []CVERule {
	enabled := make([]CVERule, 0)
	for _, rule := range l.rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}

// ReloadRules 重新加载规则
func (l *CVELoader) ReloadRules() error {
	l.rules = make([]CVERule, 0)
	return l.LoadRules()
}

// getDefaultCVERules 获取默认的 CVE 规则（后备方案）
func getDefaultCVERules() []CVERule {
	// 返回一些基本的 CVE 规则作为后备
	return []CVERule{
		{
			ServicePattern:  "SSH",
			VersionPattern:  "OpenSSH_7.4",
			CVEID:           "CVE-2018-15473",
			CVSS:            5.3,
			Severity:        "medium",
			Title:           "OpenSSH User Enumeration Vulnerability",
			Description:     "OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed.",
			Solution:        "Upgrade to OpenSSH 7.8 or later",
			AffectedVersion: "OpenSSH <= 7.7",
			Enabled:         true,
		},
	}
}
