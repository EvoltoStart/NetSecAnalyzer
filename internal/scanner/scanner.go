package scanner

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"netsecanalyzer/pkg/utils"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/ssh"
)

// Scanner 漏洞扫描器
type Scanner struct {
	MaxConcurrent int
	Timeout       time.Duration
	RateLimit     int
	Progress      func(current, total int)
	CANScanner    *CANScanner
	RS485Scanner  *RS485Scanner
	cveLoader     *CVELoader
}

// NewScanner 创建扫描器
func NewScanner(maxConcurrent int, timeout time.Duration, rateLimit int) *Scanner {
	// 创建 CVE 加载器
	cveLoader := NewCVELoader("configs/cve_rules")
	if err := cveLoader.LoadRules(); err != nil {
		logger.GetLogger().Errorf("Failed to load CVE rules: %v", err)
	}

	return &Scanner{
		MaxConcurrent: maxConcurrent,
		Timeout:       timeout,
		RateLimit:     rateLimit,
		cveLoader:     cveLoader,
	}
}

// SetCANScanner 设置 CAN 扫描器
func (s *Scanner) SetCANScanner(iface string) {
	s.CANScanner = NewCANScanner(iface, s.Timeout, s.MaxConcurrent)
}

// SetRS485Scanner 设置 RS485 扫描器
func (s *Scanner) SetRS485Scanner(port string, baudRate int) {
	s.RS485Scanner = NewRS485Scanner(port, baudRate, s.Timeout, s.MaxConcurrent)
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
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Port    int      `json:"port"`
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Banner  string   `json:"banner,omitempty"`
	CPE     string   `json:"cpe,omitempty"`
	TLSInfo *TLSInfo `json:"tls_info,omitempty"`
}

// TLSInfo TLS 信息
type TLSInfo struct {
	Version            string   `json:"version"`             // TLS 版本
	CipherSuite        string   `json:"cipher_suite"`        // 加密套件
	CertIssuer         string   `json:"cert_issuer"`         // 证书颁发者
	CertSubject        string   `json:"cert_subject"`        // 证书主题
	CertExpiry         string   `json:"cert_expiry"`         // 证书过期时间
	CertDNSNames       []string `json:"cert_dns_names"`      // 证书 DNS 名称
	CertExpired        bool     `json:"cert_expired"`        // 证书是否过期
	CertSelfSigned     bool     `json:"cert_self_signed"`    // 是否自签名证书
	WeakCipher         bool     `json:"weak_cipher"`         // 是否使用弱加密套件
	DeprecatedProtocol bool     `json:"deprecated_protocol"` // 是否使用过时协议
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
					// 端口开放，尝试识别服务和抓取 Banner
					serviceName := getServiceName(p)
					version := ""
					banner := ""

					// 尝试抓取 Banner 和识别版本
					serviceInfo := s.identifyService(target, p)
					if serviceInfo != nil {
						if serviceInfo.Version != "" {
							version = serviceInfo.Version
						}
						if serviceInfo.Banner != "" {
							banner = serviceInfo.Banner
						}
						if serviceInfo.Name != "" && serviceInfo.Name != "Unknown" {
							serviceName = serviceInfo.Name
						}
					}

					portInfo := PortInfo{
						Port:     p,
						Protocol: "TCP",
						State:    "open",
						Service:  serviceName,
						Version:  version,
						Banner:   banner,
					}
					mu.Lock()
					result.OpenPorts = append(result.OpenPorts, portInfo)
					mu.Unlock()
					logger.GetLogger().Debugf("Found open port: %s:%d (service: %s, version: %s)",
						target, p, serviceName, version)
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

// scanPort 扫描单个 TCP 端口
func (s *Scanner) scanPort(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanUDPPort 扫描单个 UDP 端口
func (s *Scanner) scanUDPPort(host string, port int) (bool, string) {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("udp", address, s.Timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// 根据端口发送特定的探测包
	probe := s.getUDPProbe(port)

	// 发送探测包
	_, err = conn.Write(probe)
	if err != nil {
		return false, ""
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	// 读取响应
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		// UDP 端口可能开放但不响应，或者被过滤
		// 如果收到 ICMP port unreachable，net.Read 会返回错误
		return false, ""
	}

	// 收到响应说明端口开放
	return true, string(buffer[:n])
}

// probeTLS 探测 TLS 服务
func (s *Scanner) probeTLS(host string, port int) *TLSInfo {
	address := fmt.Sprintf("%s:%d", host, port)

	// 创建 TLS 配置
	config := &tls.Config{
		InsecureSkipVerify: true, // 跳过证书验证以获取证书信息
		ServerName:         host,
	}

	// 建立 TLS 连接
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: s.Timeout}, "tcp", address, config)
	if err != nil {
		logger.GetLogger().Debugf("TLS handshake failed for %s: %v", address, err)
		return nil
	}
	defer conn.Close()

	// 获取连接状态
	state := conn.ConnectionState()

	// 获取 TLS 版本
	tlsVersion := getTLSVersionString(state.Version)

	// 获取加密套件
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)

	// 检查是否使用弱加密套件
	weakCipher := isWeakCipher(state.CipherSuite)

	// 检查是否使用过时协议
	deprecatedProtocol := state.Version < tls.VersionTLS12

	tlsInfo := &TLSInfo{
		Version:            tlsVersion,
		CipherSuite:        cipherSuite,
		WeakCipher:         weakCipher,
		DeprecatedProtocol: deprecatedProtocol,
	}

	// 获取证书信息
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		tlsInfo.CertIssuer = cert.Issuer.String()
		tlsInfo.CertSubject = cert.Subject.String()
		tlsInfo.CertExpiry = cert.NotAfter.Format("2006-01-02 15:04:05")
		tlsInfo.CertDNSNames = cert.DNSNames
		tlsInfo.CertExpired = time.Now().After(cert.NotAfter)

		// 检查是否自签名
		tlsInfo.CertSelfSigned = cert.Issuer.String() == cert.Subject.String()
	}

	return tlsInfo
}

// getTLSVersionString 获取 TLS 版本字符串
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// isWeakCipher 检查是否为弱加密套件
func isWeakCipher(cipherSuite uint16) bool {
	// 弱加密套件列表（使用 RC4, DES, 3DES, NULL 等）
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256, // CBC 模式也被认为较弱
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	for _, weak := range weakCiphers {
		if cipherSuite == weak {
			return true
		}
	}

	return false
}

// getUDPProbe 获取 UDP 探测包
func (s *Scanner) getUDPProbe(port int) []byte {
	switch port {
	case 53: // DNS
		// DNS 查询包：查询 example.com 的 A 记录
		return []byte{
			0x00, 0x00, // Transaction ID
			0x01, 0x00, // Flags: standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			// Query: example.com
			0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
			0x03, 0x63, 0x6f, 0x6d, 0x00,
			0x00, 0x01, // Type: A
			0x00, 0x01, // Class: IN
		}

	case 161: // SNMP
		// SNMP GetRequest for sysDescr.0
		return []byte{
			0x30, 0x26, // SEQUENCE
			0x02, 0x01, 0x00, // Version: 1
			0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community: public
			0xa0, 0x19, // GetRequest PDU
			0x02, 0x01, 0x01, // Request ID
			0x02, 0x01, 0x00, // Error status: 0
			0x02, 0x01, 0x00, // Error index: 0
			0x30, 0x0e, // Variable bindings
			0x30, 0x0c,
			0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: sysDescr.0
			0x05, 0x00, // NULL
		}

	case 123: // NTP
		// NTP version 3 client request
		return []byte{
			0x1b, // LI=0, VN=3, Mode=3 (client)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}

	case 137: // NetBIOS Name Service
		// NetBIOS Name Query
		return []byte{
			0x00, 0x00, // Transaction ID
			0x00, 0x10, // Flags: query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x00,
			0x00, 0x21, // Type: NB
			0x00, 0x01, // Class: IN
		}

	case 69: // TFTP
		// TFTP Read Request
		return []byte{
			0x00, 0x01, // Opcode: RRQ
			0x74, 0x65, 0x73, 0x74, 0x00, // Filename: "test"
			0x6f, 0x63, 0x74, 0x65, 0x74, 0x00, // Mode: "octet"
		}

	default:
		// 通用探测包
		return []byte("PROBE\r\n")
	}
}

// ScanUDPPorts 扫描 UDP 端口
func (s *Scanner) ScanUDPPorts(ctx context.Context, target string, ports []int) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		Target:    target,
		OpenPorts: []PortInfo{},
	}

	// 验证目标
	if !utils.ValidateIPv4(target) && !utils.ValidateDomain(target) {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	logger.GetLogger().Infof("Starting UDP port scan on %s, total ports: %d", target, len(ports))

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.MaxConcurrent)
	rateLimiter := time.NewTicker(time.Second / time.Duration(s.RateLimit))
	defer rateLimiter.Stop()

	scannedCount := 0

	for _, port := range ports {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("UDP port scan cancelled")
			return result, ctx.Err()
		case <-rateLimiter.C:
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				isOpen, banner := s.scanUDPPort(target, p)
				if isOpen {
					serviceName := getServiceName(p)

					portInfo := PortInfo{
						Port:     p,
						Protocol: "UDP",
						State:    "open",
						Service:  serviceName,
						Banner:   banner,
					}
					mu.Lock()
					result.OpenPorts = append(result.OpenPorts, portInfo)
					mu.Unlock()
					logger.GetLogger().Debugf("Found open UDP port: %s:%d (service: %s)",
						target, p, serviceName)
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
	logger.GetLogger().Infof("UDP port scan completed in %v, found %d open ports",
		result.ScanTime, len(result.OpenPorts))

	return result, nil
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

	serviceName := getServiceName(port)
	var banner string
	buffer := make([]byte, 4096)

	// 根据端口类型发送不同的探测包
	switch port {
	case 21: // FTP
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = string(buffer[:n])
		}
	case 22: // SSH
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = string(buffer[:n])
		}
	case 25, 110, 143: // SMTP, POP3, IMAP
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = string(buffer[:n])
		}
	case 80, 8080, 8000, 8888: // HTTP
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: NetSecAnalyzer/1.0\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = string(buffer[:n])
		}
	case 443, 8443: // HTTPS
		// HTTPS 需要 TLS 握手
		serviceName = "HTTPS"
		tlsInfo := s.probeTLS(host, port)
		if tlsInfo != nil {
			banner = fmt.Sprintf("TLS %s, Cipher: %s, Cert: %s",
				tlsInfo.Version, tlsInfo.CipherSuite, tlsInfo.CertSubject)
			return &ServiceInfo{
				Port:    port,
				Name:    serviceName,
				Version: tlsInfo.Version,
				Banner:  banner,
				TLSInfo: tlsInfo,
			}
		}
		banner = "HTTPS service (TLS encrypted)"
	case 3306: // MySQL
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = string(buffer[:n])
		}
	case 5432: // PostgreSQL
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = string(buffer[:n])
		}
	case 6379: // Redis
		conn.Write([]byte("INFO\r\n"))
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
		n, _ := conn.Read(buffer)
		if n > 0 {
			banner = string(buffer[:n])
		}
	default:
		// 尝试读取主动发送的 banner
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			banner = string(buffer[:n])
		} else {
			// 尝试发送 HTTP 请求
			conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
			conn.SetReadDeadline(time.Now().Add(s.Timeout))
			n, err = conn.Read(buffer)
			if err == nil && n > 0 {
				banner = string(buffer[:n])
			}
		}
	}

	version := extractVersion(banner, serviceName)

	return &ServiceInfo{
		Port:    port,
		Name:    serviceName,
		Version: version,
		Banner:  cleanBanner(banner),
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
				Port:         service.Port,
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
	logger.GetLogger().Debugf("Testing credentials for %s on %s:%d with %s/%s", service, host, port, username, password)

	switch strings.ToUpper(service) {
	case "SSH":
		return s.testSSHCredentials(host, port, username, password)
	case "FTP":
		return s.testFTPCredentials(host, port, username, password)
	case "MYSQL":
		return s.testMySQLCredentials(host, port, username, password)
	case "TELNET":
		return s.testTelnetCredentials(host, port, username, password)
	default:
		return false
	}
}

// testSSHCredentials 测试 SSH 弱密码
func (s *Scanner) testSSHCredentials(host string, port int, username, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.Timeout,
	}

	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		logger.GetLogger().Debugf("SSH auth failed for %s@%s: %v", username, address, err)
		return false
	}
	defer client.Close()

	logger.GetLogger().Warnf("SSH weak credentials found: %s@%s with password %s", username, address, password)
	return true
}

// testFTPCredentials 测试 FTP 弱密码
func (s *Scanner) testFTPCredentials(host string, port int, username, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := ftp.Dial(address, ftp.DialWithTimeout(s.Timeout))
	if err != nil {
		logger.GetLogger().Debugf("FTP connection failed to %s: %v", address, err)
		return false
	}
	defer conn.Quit()

	err = conn.Login(username, password)
	if err != nil {
		logger.GetLogger().Debugf("FTP auth failed for %s@%s: %v", username, address, err)
		return false
	}

	logger.GetLogger().Warnf("FTP weak credentials found: %s@%s with password %s", username, address, password)
	return true
}

// testMySQLCredentials 测试 MySQL 弱密码
func (s *Scanner) testMySQLCredentials(host string, port int, username, password string) bool {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", username, password, host, port)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		logger.GetLogger().Debugf("MySQL connection failed to %s:%d: %v", host, port, err)
		return false
	}
	defer db.Close()

	// 设置连接超时
	db.SetConnMaxLifetime(s.Timeout)
	db.SetMaxOpenConns(1)

	err = db.Ping()
	if err != nil {
		logger.GetLogger().Debugf("MySQL auth failed for %s@%s:%d: %v", username, host, port, err)
		return false
	}

	logger.GetLogger().Warnf("MySQL weak credentials found: %s@%s:%d with password %s", username, host, port, password)
	return true
}

// testTelnetCredentials 测试 Telnet 弱密码
func (s *Scanner) testTelnetCredentials(host string, port int, username, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		logger.GetLogger().Debugf("Telnet connection failed to %s: %v", address, err)
		return false
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(s.Timeout))

	// 读取欢迎信息
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil && err != io.EOF {
		logger.GetLogger().Debugf("Telnet read failed: %v", err)
		return false
	}

	// 发送用户名
	_, err = conn.Write([]byte(username + "\r\n"))
	if err != nil {
		return false
	}

	// 读取密码提示
	time.Sleep(100 * time.Millisecond)
	_, err = conn.Read(buffer)
	if err != nil && err != io.EOF {
		return false
	}

	// 发送密码
	_, err = conn.Write([]byte(password + "\r\n"))
	if err != nil {
		return false
	}

	// 读取响应
	time.Sleep(200 * time.Millisecond)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return false
	}

	response := string(buffer[:n])

	// 检查是否登录成功（简单判断）
	if strings.Contains(strings.ToLower(response), "login incorrect") ||
		strings.Contains(strings.ToLower(response), "authentication failed") {
		return false
	}

	// 如果没有明确的失败信息，认为可能成功
	if strings.Contains(response, "$") || strings.Contains(response, "#") || strings.Contains(response, ">") {
		logger.GetLogger().Warnf("Telnet weak credentials found: %s@%s with password %s", username, address, password)
		return true
	}

	return false
}

// checkKnownVulnerabilities 检查已知漏洞
func (s *Scanner) checkKnownVulnerabilities(target string, service ServiceInfo) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// 获取启用的 CVE 规则
	rules := s.cveLoader.GetEnabledRules()

	logger.GetLogger().Debugf("Checking CVE for service: %s, version: %s, banner: %s (total %d rules)",
		service.Name, service.Version, service.Banner[:min(len(service.Banner), 50)], len(rules))

	// 遍历 CVE 规则库进行匹配
	matchedRules := 0
	for _, rule := range rules {
		// 检查服务名称是否匹配
		serviceMatch := false
		if rule.ServicePattern != "" {
			serviceMatch = strings.Contains(strings.ToLower(service.Name), strings.ToLower(rule.ServicePattern)) ||
				strings.Contains(strings.ToLower(service.Banner), strings.ToLower(rule.ServicePattern))
		} else {
			// 如果规则没有指定服务名称，则不匹配（避免误报）
			continue
		}

		if !serviceMatch {
			continue
		}

		matchedRules++
		logger.GetLogger().Debugf("Service matched rule %s (pattern: %s), checking version: %s (range: %s - %s)",
			rule.CVEID, rule.ServicePattern, service.Version, rule.VersionMin, rule.VersionMax)

		// 使用新的版本匹配逻辑
		if !IsVersionVulnerable(service.Version, rule) {
			logger.GetLogger().Debugf("Version %s not vulnerable to %s (range: %s - %s)",
				service.Version, rule.CVEID, rule.VersionMin, rule.VersionMax)
			continue
		}

		// 匹配成功，创建漏洞记录
		logger.GetLogger().Infof("✅ Found CVE %s for %s %s on port %d (version range: %s - %s)",
			rule.CVEID, service.Name, service.Version, service.Port, rule.VersionMin, rule.VersionMax)

		vuln := models.Vulnerability{
			Target:       fmt.Sprintf("%s:%d", target, service.Port),
			Port:         service.Port,
			VulnType:     "Known Vulnerability",
			Severity:     rule.Severity,
			CVEID:        rule.CVEID,
			CVSS:         rule.CVSS,
			Title:        rule.Title,
			Description:  fmt.Sprintf("%s\n\nAffected Version: %s\nDetected: %s %s", rule.Description, rule.AffectedVersion, service.Name, service.Version),
			Solution:     rule.Solution,
			DiscoveredAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	logger.GetLogger().Debugf("CVE check complete: %d service matches, %d vulnerabilities found",
		matchedRules, len(vulnerabilities))

	return vulnerabilities
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// checkMisconfigurations 检查配置错误
func (s *Scanner) checkMisconfigurations(target string, service ServiceInfo) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	// 配置开关：是否报告信息泄露类漏洞（默认关闭，避免误报）
	reportInfoDisclosure := false

	// 检查常见配置错误
	switch service.Name {
	case "HTTP", "HTTPS":
		// 检查是否允许目录遍历、敏感信息泄露等
		if s.checkDirectoryListing(target, service.Port) {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				Port:         service.Port,
				VulnType:     "Misconfiguration",
				Severity:     "medium",
				Title:        "Directory listing enabled",
				Description:  "Web server allows directory listing which may expose sensitive files",
				Solution:     "Disable directory listing in web server configuration",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

		// 检查敏感文件泄露
		sensitiveFiles := s.checkSensitiveFiles(target, service.Port)
		for _, file := range sensitiveFiles {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				Port:         service.Port,
				VulnType:     "Information Disclosure",
				Severity:     "high",
				Title:        fmt.Sprintf("Sensitive file exposed: %s", file),
				Description:  fmt.Sprintf("Sensitive file is accessible: %s", file),
				Solution:     "Remove or restrict access to sensitive files",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

		// 检查 HTTP 服务的版本信息泄露（默认禁用）
		if reportInfoDisclosure && service.Version != "" && strings.Contains(strings.ToLower(service.Banner), "server:") {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				Port:         service.Port,
				VulnType:     "Information Disclosure",
				Severity:     "low",
				Title:        "Server version information disclosure",
				Description:  fmt.Sprintf("Web server exposes version information: %s", service.Version),
				Solution:     "Configure web server to hide version information in HTTP headers",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

		// 检查 HTTPS/TLS 配置问题
		if service.Name == "HTTPS" && service.TLSInfo != nil {
			tlsVulns := s.checkTLSVulnerabilities(target, service)
			vulnerabilities = append(vulnerabilities, tlsVulns...)
		}

	case "FTP":
		// 检查匿名登录
		if s.checkAnonymousFTP(target, service.Port) {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				Port:         service.Port,
				VulnType:     "Misconfiguration",
				Severity:     "high",
				Title:        "Anonymous FTP access enabled",
				Description:  "FTP server allows anonymous access",
				Solution:     "Disable anonymous FTP access",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

	case "SSH":
		// 检查 SSH 版本信息泄露（默认禁用）
		if reportInfoDisclosure && service.Version != "" && strings.Contains(strings.ToLower(service.Version), "openssh") {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				Port:         service.Port,
				VulnType:     "Information Disclosure",
				Severity:     "low",
				Title:        "SSH version information exposed",
				Description:  fmt.Sprintf("SSH server exposes version: %s", service.Version),
				Solution:     "Consider updating to the latest SSH version and configure to hide version details",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

	case "Telnet":
		// Telnet 本身就是不安全的（默认禁用，因为这不是真正的漏洞）
		if reportInfoDisclosure {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				Port:         service.Port,
				VulnType:     "Insecure Protocol",
				Severity:     "high",
				Title:        "Insecure Telnet service detected",
				Description:  "Telnet transmits data in plaintext, including passwords",
				Solution:     "Disable Telnet and use SSH instead",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}

	case "MySQL", "PostgreSQL", "Redis":
		// 数据库服务暴露检测（默认禁用）
		if reportInfoDisclosure {
			vuln := models.Vulnerability{
				Target:       fmt.Sprintf("%s:%d", target, service.Port),
				Port:         service.Port,
				VulnType:     "Exposure",
				Severity:     "medium",
				Title:        fmt.Sprintf("%s database service exposed", service.Name),
				Description:  fmt.Sprintf("%s database is accessible from external network", service.Name),
				Solution:     "Restrict database access to trusted networks only using firewall rules",
				DiscoveredAt: time.Now(),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// checkTLSVulnerabilities 检查 TLS 相关漏洞
func (s *Scanner) checkTLSVulnerabilities(target string, service ServiceInfo) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	if service.TLSInfo == nil {
		return vulnerabilities
	}

	tlsInfo := service.TLSInfo

	// 检查证书过期
	if tlsInfo.CertExpired {
		vuln := models.Vulnerability{
			Target:       fmt.Sprintf("%s:%d", target, service.Port),
			Port:         service.Port,
			VulnType:     "TLS Misconfiguration",
			Severity:     "high",
			Title:        "Expired SSL/TLS Certificate",
			Description:  fmt.Sprintf("The SSL/TLS certificate has expired on %s", tlsInfo.CertExpiry),
			Solution:     "Renew the SSL/TLS certificate immediately",
			DiscoveredAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// 检查自签名证书
	if tlsInfo.CertSelfSigned {
		vuln := models.Vulnerability{
			Target:       fmt.Sprintf("%s:%d", target, service.Port),
			Port:         service.Port,
			VulnType:     "TLS Misconfiguration",
			Severity:     "medium",
			Title:        "Self-Signed SSL/TLS Certificate",
			Description:  "The server is using a self-signed certificate which is not trusted by browsers",
			Solution:     "Use a certificate from a trusted Certificate Authority (CA)",
			DiscoveredAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// 检查过时的 TLS 协议
	if tlsInfo.DeprecatedProtocol {
		vuln := models.Vulnerability{
			Target:       fmt.Sprintf("%s:%d", target, service.Port),
			Port:         service.Port,
			VulnType:     "TLS Misconfiguration",
			Severity:     "high",
			Title:        "Deprecated TLS Protocol Version",
			Description:  fmt.Sprintf("Server supports deprecated TLS protocol: %s. TLS 1.2 or higher is recommended", tlsInfo.Version),
			Solution:     "Disable TLS 1.0 and TLS 1.1, enable only TLS 1.2 and TLS 1.3",
			DiscoveredAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// 检查弱加密套件
	if tlsInfo.WeakCipher {
		vuln := models.Vulnerability{
			Target:       fmt.Sprintf("%s:%d", target, service.Port),
			Port:         service.Port,
			VulnType:     "TLS Misconfiguration",
			Severity:     "medium",
			Title:        "Weak TLS Cipher Suite",
			Description:  fmt.Sprintf("Server uses weak cipher suite: %s", tlsInfo.CipherSuite),
			Solution:     "Configure server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305)",
			DiscoveredAt: time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// 检查证书即将过期（30天内）
	if !tlsInfo.CertExpired && tlsInfo.CertExpiry != "" {
		expiryTime, err := time.Parse("2006-01-02 15:04:05", tlsInfo.CertExpiry)
		if err == nil {
			daysUntilExpiry := int(time.Until(expiryTime).Hours() / 24)
			if daysUntilExpiry > 0 && daysUntilExpiry <= 30 {
				vuln := models.Vulnerability{
					Target:       fmt.Sprintf("%s:%d", target, service.Port),
					Port:         service.Port,
					VulnType:     "TLS Misconfiguration",
					Severity:     "low",
					Title:        "SSL/TLS Certificate Expiring Soon",
					Description:  fmt.Sprintf("The SSL/TLS certificate will expire in %d days on %s", daysUntilExpiry, tlsInfo.CertExpiry),
					Solution:     "Renew the SSL/TLS certificate before it expires",
					DiscoveredAt: time.Now(),
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

// checkDirectoryListing 检查目录列表
func (s *Scanner) checkDirectoryListing(host string, port int) bool {
	// 构建 URL
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	// 创建 HTTP 客户端
	client := &http.Client{
		Timeout: s.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		logger.GetLogger().Debugf("HTTP request failed to %s: %v", url, err)
		return false
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	bodyStr := string(body)

	// 检查常见的目录列表特征
	indicators := []string{
		"Index of /",
		"Directory listing for",
		"<title>Index of",
		"Parent Directory",
		"[To Parent Directory]",
		"<h1>Index of",
	}

	for _, indicator := range indicators {
		if strings.Contains(bodyStr, indicator) {
			logger.GetLogger().Infof("Directory listing detected on %s", url)
			return true
		}
	}

	return false
}

// checkAnonymousFTP 检查匿名 FTP
func (s *Scanner) checkAnonymousFTP(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := ftp.Dial(address, ftp.DialWithTimeout(s.Timeout))
	if err != nil {
		logger.GetLogger().Debugf("FTP connection failed to %s: %v", address, err)
		return false
	}
	defer conn.Quit()

	// 尝试匿名登录
	err = conn.Login("anonymous", "anonymous@example.com")
	if err != nil {
		logger.GetLogger().Debugf("FTP anonymous login failed to %s: %v", address, err)
		return false
	}

	logger.GetLogger().Warnf("FTP anonymous access enabled on %s", address)
	return true
}

// checkSensitiveFiles 检查敏感文件泄露
func (s *Scanner) checkSensitiveFiles(host string, port int) []string {
	var exposedFiles []string

	// 常见敏感文件列表
	sensitiveFiles := []string{
		"/.git/config",
		"/.git/HEAD",
		"/.env",
		"/.env.local",
		"/.env.production",
		"/config.php",
		"/wp-config.php",
		"/web.config",
		"/phpinfo.php",
		"/info.php",
		"/.htaccess",
		"/robots.txt",
		"/.DS_Store",
		"/backup.sql",
		"/database.sql",
		"/dump.sql",
		"/admin",
		"/phpmyadmin",
		"/.svn/entries",
	}

	// 构建基础 URL
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	// 创建 HTTP 客户端
	client := &http.Client{
		Timeout: s.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向
		},
	}

	// 检查每个敏感文件
	for _, file := range sensitiveFiles {
		url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, file)

		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// 如果返回 200 OK，说明文件可访问
		if resp.StatusCode == 200 {
			logger.GetLogger().Warnf("Sensitive file exposed: %s", url)
			exposedFiles = append(exposedFiles, file)
		}
	}

	return exposedFiles
}

// getServiceName 根据端口获取服务名
func getServiceName(port int) string {
	services := map[int]string{
		// TCP 服务
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		80:    "HTTP",
		110:   "POP3",
		139:   "NetBIOS",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		502:   "Modbus",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		6379:  "Redis",
		8080:  "HTTP",
		8443:  "HTTPS",
		9200:  "Elasticsearch",
		27017: "MongoDB",
		11211: "Memcached",

		// UDP 服务
		53:   "DNS",
		67:   "DHCP",
		68:   "DHCP",
		69:   "TFTP",
		123:  "NTP",
		137:  "NetBIOS-NS",
		138:  "NetBIOS-DGM",
		161:  "SNMP",
		162:  "SNMP-Trap",
		500:  "IKE",
		514:  "Syslog",
		520:  "RIP",
		1900: "SSDP",
		4500: "IPSec-NAT-T",
		5353: "mDNS",
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
func extractVersion(banner string, serviceName string) string {
	if banner == "" {
		return ""
	}

	// 根据服务类型提取版本信息
	switch serviceName {
	case "SSH":
		// SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
		if strings.HasPrefix(banner, "SSH-") {
			// 去掉换行符
			banner = strings.TrimSpace(strings.Split(banner, "\n")[0])
			// 按 "-" 分割
			parts := strings.Split(banner, "-")
			if len(parts) >= 3 {
				// 提取 "OpenSSH_8.2p1"，去掉后面的空格和其他信息
				versionPart := strings.Split(parts[2], " ")[0]

				// 进一步清理：去掉 "p1" 等补丁版本号，只保留主版本号
				// OpenSSH_8.2p1 -> 8.2
				if strings.Contains(versionPart, "OpenSSH_") {
					versionPart = strings.TrimPrefix(versionPart, "OpenSSH_")
					// 去掉 p1, p2 等补丁号
					if idx := strings.Index(versionPart, "p"); idx > 0 {
						versionPart = versionPart[:idx]
					}
				}

				return versionPart
			}
		}
	case "HTTP", "HTTPS":
		// Server: Apache/2.4.41 (Ubuntu)
		// Server: nginx/1.20.1
		lines := strings.Split(banner, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				serverInfo := strings.TrimSpace(line[7:])
				// 去掉括号中的信息，只保留 "Apache/2.4.41" 或 "nginx/1.20.1"
				serverInfo = strings.Split(serverInfo, " ")[0]
				serverInfo = strings.Split(serverInfo, "(")[0]
				return strings.TrimSpace(serverInfo)
			}
		}
	case "FTP":
		// 220 ProFTPD 1.3.5 Server
		// 220 vsftpd 2.3.4
		if len(banner) > 4 {
			parts := strings.Fields(banner)
			if len(parts) >= 2 {
				// 提取服务名和版本号
				version := strings.Join(parts[1:], " ")
				// 去掉 "Server" 等后缀
				version = strings.Split(version, "Server")[0]
				return strings.TrimSpace(version)
			}
		}
	case "MySQL":
		// MySQL 版本在握手包中，通常难以直接提取
		// 如果 banner 中包含版本号，尝试提取
		if strings.Contains(banner, "mysql") || strings.Contains(banner, "MySQL") {
			// 尝试提取版本号 (例如: 5.7.33, 8.0.21)
			re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
			if matches := re.FindStringSubmatch(banner); len(matches) > 0 {
				return "MySQL " + matches[1]
			}
			return "MySQL"
		}
	case "Redis":
		// redis_version:6.0.16
		lines := strings.Split(banner, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "redis_version:") {
				version := strings.TrimSpace(line[14:])
				return "Redis " + version
			}
		}
	case "PostgreSQL":
		// PostgreSQL 版本提取
		if strings.Contains(banner, "PostgreSQL") {
			re := regexp.MustCompile(`PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)`)
			if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
				return "PostgreSQL " + matches[1]
			}
			return "PostgreSQL"
		}
	case "MongoDB":
		// MongoDB 版本提取
		if strings.Contains(banner, "MongoDB") {
			re := regexp.MustCompile(`MongoDB\s+(\d+\.\d+\.\d+)`)
			if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
				return "MongoDB " + matches[1]
			}
			return "MongoDB"
		}
	}

	// 通用版本提取：尝试使用正则表达式提取版本号
	// 匹配常见的版本号格式：x.y.z 或 x.y
	re := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
	if matches := re.FindStringSubmatch(banner); len(matches) > 0 {
		return matches[1]
	}

	// 如果无法提取版本号，返回空字符串而不是整个 banner
	// 这样可以避免误匹配
	return ""
}

// cleanBanner 清理 banner 字符串
func cleanBanner(banner string) string {
	if banner == "" {
		return ""
	}

	// 移除不可打印字符
	cleaned := strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, banner)

	// 限制长度
	if len(cleaned) > 500 {
		return cleaned[:500] + "..."
	}

	return strings.TrimSpace(cleaned)
}
