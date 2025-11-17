package scanner

import (
	"regexp"
	"strconv"
	"strings"
)

// Version 版本结构
type Version struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

// ParseVersion 解析版本号
// 支持多种格式：
// - OpenSSH_7.4p1 -> 7.4.0
// - nginx/1.20.1 -> 1.20.1
// - Apache/2.4.41 -> 2.4.41
// - 5.6 -> 5.6.0
func ParseVersion(versionStr string) *Version {
	if versionStr == "" {
		return nil
	}

	// 提取数字部分
	// 匹配模式：数字.数字.数字 或 数字.数字
	re := regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
	matches := re.FindStringSubmatch(versionStr)

	if len(matches) < 3 {
		return nil
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch := 0
	if len(matches) > 3 && matches[3] != "" {
		patch, _ = strconv.Atoi(matches[3])
	}

	return &Version{
		Major: major,
		Minor: minor,
		Patch: patch,
		Raw:   versionStr,
	}
}

// Compare 比较两个版本
// 返回值：
//
//	-1: v1 < v2
//	 0: v1 == v2
//	 1: v1 > v2
func (v *Version) Compare(other *Version) int {
	if v == nil || other == nil {
		return 0
	}

	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}

	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}

	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}

	return 0
}

// IsInRange 检查版本是否在指定范围内
// minVersion 和 maxVersion 都是包含的（inclusive）
func IsVersionInRange(version, minVersion, maxVersion string) bool {
	v := ParseVersion(version)
	if v == nil {
		return false
	}

	// 如果没有指定范围，返回 true
	if minVersion == "" && maxVersion == "" {
		return true
	}

	// 检查最小版本
	if minVersion != "" {
		minV := ParseVersion(minVersion)
		if minV != nil && v.Compare(minV) < 0 {
			return false
		}
	}

	// 检查最大版本
	if maxVersion != "" {
		maxV := ParseVersion(maxVersion)
		if maxV != nil && v.Compare(maxV) > 0 {
			return false
		}
	}

	return true
}

// MatchesPattern 检查版本是否匹配模式
// 使用简单的字符串包含匹配（用于向后兼容）
func MatchesPattern(version, pattern string) bool {
	if pattern == "" {
		return true
	}
	return strings.Contains(strings.ToLower(version), strings.ToLower(pattern))
}

// IsVersionVulnerable 检查版本是否受 CVE 影响
// 优先使用版本范围，如果没有则使用模式匹配
func IsVersionVulnerable(serviceVersion string, rule CVERule) bool {
	// 如果服务版本为空，无法判断
	if serviceVersion == "" {
		return false
	}

	// 优先使用版本范围匹配
	if rule.VersionMin != "" || rule.VersionMax != "" {
		return IsVersionInRange(serviceVersion, rule.VersionMin, rule.VersionMax)
	}

	// 如果没有版本范围，使用模式匹配
	if rule.VersionPattern != "" {
		return MatchesPattern(serviceVersion, rule.VersionPattern)
	}

	// 如果既没有版本范围也没有模式，则不匹配
	// 这样可以避免误报
	return false
}
