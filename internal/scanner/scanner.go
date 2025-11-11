package scanner

import (
	"context"
	"fmt"
	"net"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"netsecanalyzer/pkg/utils"
	"sync"
	"time"
)

// Scanner 漏洞扫描器
type Scanner struct {
	MaxConcurrent int
	Timeout       time.Duration
	RateLimit     int
	Progress      func(current, total int)
}

// NewScanner 创建扫描器
func NewScanner(maxConcurrent int, timeout time.Duration, rateLimit int) *Scanner {
	return &Scanner{
		MaxConcurrent: maxConcurrent,
		Timeout:       timeout,
		RateLimit:     rateLimit,
	}
}

// ScanResult 扫描结果
type ScanResult struct {
	Target          string                 `json:"target"`
	OpenPorts       []PortInfo             `json:"open_ports"`
	Services        []ServiceInfo          `json:"services"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	ScanTime        time.Duration          `json:"scan_time"`
	Error           string                 `json:"error,omitempty"`
}

// PortInfo 端口信息
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

// ScanPorts 扫描端口
func (s *Scanner) ScanPorts(ctx context.Context, target string, ports []int) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		Target:    target,
		OpenPorts: []PortInfo{},
	}

	// 验证目标
	if !utils.ValidateIPv4(target) && !utils.ValidateDomain(target) {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	logger.GetLogger().Infof("Starting port scan on %s, total ports: %d", target, len(ports))

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.MaxConcurrent)
	rateLimiter := time.NewTicker(time.Second / time.Duration(s.RateLimit))
	defer rateLimiter.Stop()

	scannedCount := 0

	for _, port := range ports {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Port scan cancelled")
			return result, ctx.Err()
		case <-rateLimiter.C:
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				if s.scanPort(target, p) {
					portInfo := PortInfo{
						Port:     p,
						Protocol: "TCP",
						State:    "open",
						Service:  getServiceName(p),
					}
					mu.Lock()
					result.OpenPorts = append(result.OpenPorts, portInfo)
					mu.Unlock()
					logger.GetLogger().Debugf("Found open port: %s:%d", target, p)
				}

				mu.Lock()
				scannedCount++
				if s.Progress != nil {
					s.Progress(scannedCount, len(ports))
				}
				mu.Unlock()
			}(port)
		}
	}

	wg.Wait()
	result.ScanTime = time.Since(startTime)

	logger.GetLogger().Infof("Port scan completed on %s: %d open ports found in %s",
		target, len(result.OpenPorts), result.ScanTime)

	return result, nil
}

// scanPort 扫描单个端口
func (s *Scanner) scanPort(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ScanServices 服务识别
func (s *Scanner) ScanServices(ctx context.Context, target string, ports []int) ([]ServiceInfo, error) {
	var services []ServiceInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, s.MaxConcurrent)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return services, ctx.Err()
		default:
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				serviceInfo := s.identifyService(target, p)
				if serviceInfo != nil {
					mu.Lock()
					services = append(services, *serviceInfo)
					mu.Unlock()
				}
			}(port)
		}
	}

	wg.Wait()
	return services, nil
}

// identifyService 识别服务
func (s *Scanner) identifyService(host string, port int) *ServiceInfo {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	// 尝试抓取 banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	var banner string
	if err == nil && n > 0 {
		banner = string(buffer[:n])
	}

	// 如果没有主动发送 banner，尝试发送探测包
	if banner == "" {
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
		n, err = conn.Read(buffer)
		if err == nil && n > 0 {
			banner = string(buffer[:n])
		}
	}

	serviceName := getServiceName(port)
	version := extractVersion(banner)

	return &ServiceInfo{
		Port:    port,
		Name:    serviceName,
		Version: version,
		Banner:  banner,
	}
}

// DetectVulnerabilities 漏洞检测
func (s *Scanner) DetectVulnerabilities(ctx context.Context, target string, services []ServiceInfo) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	for _, service := range services {
		// 检查弱密码
		if isAuthService(service.Name) {
			vulns := s.checkWeakCredentials(target, service)
			vulnerabilities = append(vulnerabilities, vulns...)
		}

		// 检查已知漏洞
		vulns := s.checkKnownVulnerabilities(target, service)
		vulnerabilities = append(vulnerabilities, vulns...)

		// 检查配置错误
		vulns = s.checkMisconfigurations(target, service)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

// checkWeakCredentials 检查弱密码
func (s *Scanner) checkWeakCredentials(target string, service ServiceInfo) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// 常见弱密码列表
	weakPasswords := [][]string{
		{"admin", "admin"},
		{"root", "root"},
		{"admin", "password"},
		{"admin", "123456"},
	}

	for _, cred := range weakPasswords {
		username, password := cred[0], cred[1]

		// 根据服务类型测试
		if s.testCredentials(target, service.Port, service.Name, username, password) {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				VulnType:     "Weak Credentials",
				Severity:     "high",
				Title:        fmt.Sprintf("Weak credentials detected on %s", service.Name),
				Description:  fmt.Sprintf("Service allows login with weak credentials: %s/%s", username, password),
				Solution:     "Change default credentials and enforce strong password policy",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
			break // 找到一个就够了
		}
	}

	return vulnerabilities
}

// testCredentials 测试凭据
func (s *Scanner) testCredentials(host string, port int, service, username, password string) bool {
	// 这里只是示例框架，实际实现需要根据不同协议进行认证测试
	// 例如：SSH、FTP、Telnet、MySQL 等
	logger.GetLogger().Debugf("Testing credentials for %s on %s:%d", service, host, port)
	return false // 默认返回失败
}

// checkKnownVulnerabilities 检查已知漏洞
func (s *Scanner) checkKnownVulnerabilities(target string, service ServiceInfo) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// 基于服务版本匹配 CVE
	// 这里是简化版本，实际应该查询 CVE 数据库
	if service.Version != "" {
		logger.GetLogger().Debugf("Checking known vulnerabilities for %s %s", service.Name, service.Version)

		// 示例：检查 Apache 版本
		if service.Name == "HTTP" && service.Version != "" {
			// 这里应该查询 CVE 数据库
			// 暂时返回空列表
		}
	}

	return vulnerabilities
}

// checkMisconfigurations 检查配置错误
func (s *Scanner) checkMisconfigurations(target string, service ServiceInfo) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// 检查常见配置错误
	switch service.Name {
	case "HTTP", "HTTPS":
		// 检查是否允许目录遍历、敏感信息泄露等
		if s.checkDirectoryListing(target, service.Port) {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				VulnType:     "Misconfiguration",
				Severity:     "medium",
				Title:        "Directory listing enabled",
				Description:  "Web server allows directory listing which may expose sensitive files",
				Solution:     "Disable directory listing in web server configuration",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

	case "FTP":
		// 检查匿名登录
		if s.checkAnonymousFTP(target, service.Port) {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				VulnType:     "Misconfiguration",
				Severity:     "high",
				Title:        "Anonymous FTP access enabled",
				Description:  "FTP server allows anonymous access",
				Solution:     "Disable anonymous FTP access",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// checkDirectoryListing 检查目录列表
func (s *Scanner) checkDirectoryListing(host string, port int) bool {
	// 简化实现
	return false
}

// checkAnonymousFTP 检查匿名 FTP
func (s *Scanner) checkAnonymousFTP(host string, port int) bool {
	// 简化实现
	return false
}

// getServiceName 根据端口获取服务名
func getServiceName(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		502:  "Modbus",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP",
		8443: "HTTPS",
	}

	if name, exists := services[port]; exists {
		return name
	}
	return "Unknown"
}

// isAuthService 判断是否为需要认证的服务
func isAuthService(service string) bool {
	authServices := []string{"SSH", "FTP", "Telnet", "MySQL", "PostgreSQL", "Redis", "RDP"}
	return utils.Contains(authServices, service)
}

// extractVersion 从 banner 中提取版本信息
func extractVersion(banner string) string {
	// 简化实现，实际应该使用正则表达式提取版本号
	if len(banner) > 100 {
		return banner[:100]
	}
	return banner
}
