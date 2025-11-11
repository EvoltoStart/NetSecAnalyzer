package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParseIPRange 解析 IP 范围
// 支持格式: 192.168.1.1, 192.168.1.0/24, 192.168.1.1-192.168.1.254
func ParseIPRange(ipRange string) ([]string, error) {
	var ips []string

	// CIDR 格式
	if strings.Contains(ipRange, "/") {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, err
		}
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
		return ips, nil
	}

	// 范围格式
	if strings.Contains(ipRange, "-") {
		parts := strings.Split(ipRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range format")
		}
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP address")
		}
		for ip := startIP; !ip.Equal(endIP); inc(ip) {
			ips = append(ips, ip.String())
		}
		ips = append(ips, endIP.String())
		return ips, nil
	}

	// 单个 IP
	if net.ParseIP(ipRange) != nil {
		return []string{ipRange}, nil
	}

	return nil, fmt.Errorf("invalid IP range format")
}

// inc 增加 IP 地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParsePortRange 解析端口范围
// 支持格式: 80, 80-443, 80,443,8080
func ParsePortRange(portRange string) ([]int, error) {
	var ports []int
	portMap := make(map[int]bool)

	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// 范围格式
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format")
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, err
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("port out of range: %d", p)
				}
				if !portMap[p] {
					ports = append(ports, p)
					portMap[p] = true
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			if !portMap[port] {
				ports = append(ports, port)
				portMap[port] = true
			}
		}
	}

	return ports, nil
}

// IsPrivateIP 判断是否为私有 IP
func IsPrivateIP(ip string) bool {
	privateIPBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	for _, block := range privateIPBlocks {
		_, ipNet, _ := net.ParseCIDR(block)
		if ipNet.Contains(ipAddr) {
			return true
		}
	}
	return false
}

// MD5Hash 计算 MD5 哈希
func MD5Hash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// ValidateMAC 验证 MAC 地址格式
func ValidateMAC(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

// ValidateIPv4 验证 IPv4 地址格式
func ValidateIPv4(ip string) bool {
	ipAddr := net.ParseIP(ip)
	return ipAddr != nil && ipAddr.To4() != nil
}

// ValidateIPv6 验证 IPv6 地址格式
func ValidateIPv6(ip string) bool {
	ipAddr := net.ParseIP(ip)
	return ipAddr != nil && ipAddr.To4() == nil
}

// ValidateDomain 验证域名格式
func ValidateDomain(domain string) bool {
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	return domainRegex.MatchString(domain)
}

// FormatBytes 格式化字节大小
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration 格式化时间间隔
func FormatDuration(duration time.Duration) string {
	if duration < time.Second {
		return fmt.Sprintf("%dms", duration.Milliseconds())
	}
	if duration < time.Minute {
		return fmt.Sprintf("%.1fs", duration.Seconds())
	}
	if duration < time.Hour {
		return fmt.Sprintf("%.1fm", duration.Minutes())
	}
	return fmt.Sprintf("%.1fh", duration.Hours())
}

// Paginate 分页辅助函数
func Paginate(page, pageSize int) (offset int, limit int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	offset = (page - 1) * pageSize
	limit = pageSize
	return
}

// Contains 检查切片是否包含元素
func Contains[T comparable](slice []T, item T) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// Unique 去重切片
func Unique[T comparable](slice []T) []T {
	keys := make(map[T]bool)
	list := []T{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
