package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"netsecanalyzer/internal/analyzer"
	"netsecanalyzer/internal/capture"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"
	wsHub "netsecanalyzer/internal/websocket"
	"netsecanalyzer/pkg/logger"
	"netsecanalyzer/pkg/storage"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// 验证辅助函数

// isValidInterface 验证网络接口名称
func isValidInterface(iface string) bool {
	if iface == "" {
		return false
	}

	// 检查接口名称格式（字母数字和连字符，长度限制）
	if len(iface) > 50 {
		return false
	}

	// 允许的接口名称模式：eth0, wlan0, can0, any, lo, enp0s3 等
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	if !validPattern.MatchString(iface) {
		return false
	}

	// 可选：检查接口是否真实存在（对于 IP 捕获）
	// 注意：对于 "any" 这样的特殊接口，不需要检查
	if iface == "any" || iface == "lo" {
		return true
	}

	// 尝试获取接口列表验证
	interfaces, err := net.Interfaces()
	if err != nil {
		// 如果无法获取接口列表，只进行格式验证
		logger.GetLogger().Warnf("Cannot get network interfaces: %v", err)
		return true
	}

	for _, i := range interfaces {
		if i.Name == iface {
			return true
		}
	}

	// 对于 CAN 和 RS485，接口可能不在标准列表中
	// 允许 can0-can9, ttyUSB0-ttyUSB9 等
	if strings.HasPrefix(iface, "can") || strings.HasPrefix(iface, "tty") {
		return true
	}

	return false
}

// isValidBPFFilter 验证 BPF 过滤器语法
func isValidBPFFilter(filter string) bool {
	if filter == "" {
		return true // 空过滤器是有效的
	}

	// 长度限制
	if len(filter) > 1000 {
		return false
	}

	// 基本的 BPF 语法检查
	// 允许的关键字和模式
	validKeywords := []string{
		"tcp", "udp", "icmp", "ip", "ip6", "arp", "rarp",
		"host", "net", "port", "src", "dst",
		"and", "or", "not",
		"portrange", "less", "greater",
	}

	// 转换为小写进行检查
	lowerFilter := strings.ToLower(filter)

	// 检查是否包含危险字符（防止命令注入）
	dangerousChars := []string{";", "|", "&", "`", "$", "()", "{}"}
	for _, char := range dangerousChars {
		if strings.Contains(filter, char) {
			return false
		}
	}

	// 检查是否至少包含一个有效关键字
	hasValidKeyword := false
	for _, keyword := range validKeywords {
		if strings.Contains(lowerFilter, keyword) {
			hasValidKeyword = true
			break
		}
	}

	// 如果包含数字（端口号或IP地址），也认为是有效的
	if regexp.MustCompile(`\d+`).MatchString(filter) {
		hasValidKeyword = true
	}

	return hasValidKeyword
}

// isValidProtocol 验证协议名称
func isValidProtocol(protocol string) bool {
	if protocol == "" {
		return false
	}

	// 支持的协议白名单
	validProtocols := map[string]bool{
		"TCP":     true,
		"UDP":     true,
		"ICMP":    true,
		"HTTP":    true,
		"HTTPS":   true,
		"DNS":     true,
		"ARP":     true,
		"TLS":     true,
		"SSH":     true,
		"FTP":     true,
		"SMTP":    true,
		"POP3":    true,
		"IMAP":    true,
		"DHCP":    true,
		"NTP":     true,
		"SNMP":    true,
		"Modbus":  true,
		"CAN":     true,
		"Unknown": true,
	}

	return validProtocols[protocol]
}

// isValidIPAddress 验证 IP 地址格式
func isValidIPAddress(addr string) bool {
	if addr == "" {
		return false
	}

	// 解析 IP 地址
	ip := net.ParseIP(addr)
	return ip != nil
}

// CaptureHandler 数据采集处理器
type CaptureHandler struct {
	activeSessions map[uint]context.CancelFunc
	payloadStorage *storage.PayloadStorage
	wsHub          *wsHub.Hub
	analyzer       *analyzer.Analyzer
	mu             sync.Mutex
}

// NewCaptureHandler 创建采集处理器
func NewCaptureHandler() *CaptureHandler {
	// 创建 Payload 存储管理器
	payloadStorage, err := storage.NewPayloadStorage("./data/payloads", 100*1024*1024, 30)
	if err != nil {
		logger.GetLogger().Errorf("Failed to create payload storage: %v", err)
	}

	// 创建 WebSocket Hub
	hub := wsHub.NewHub()
	go hub.Run()

	// 创建协议分析器
	protocolAnalyzer := analyzer.NewAnalyzer()

	return &CaptureHandler{
		activeSessions: make(map[uint]context.CancelFunc),
		payloadStorage: payloadStorage,
		wsHub:          hub,
		analyzer:       protocolAnalyzer,
	}
}

// StartCaptureRequest 启动采集请求
type StartCaptureRequest struct {
	Name   string                 `json:"name" binding:"required"`
	Type   string                 `json:"type" binding:"required,oneof=ip can rs485"`
	Config map[string]interface{} `json:"config"`
	Filter string                 `json:"filter"`
}

// StartCapture 启动数据采集
func (h *CaptureHandler) StartCapture(c *gin.Context) {
	var req StartCaptureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	// 验证输入参数
	// 验证接口名称（对于 IP 和 CAN 捕获）
	if req.Type == "ip" || req.Type == "can" {
		iface := ""
		if val, ok := req.Config["interface"].(string); ok {
			iface = val
		}

		if iface == "" {
			RespondBadRequest(c, "Interface name is required")
			return
		}

		if !isValidInterface(iface) {
			RespondBadRequest(c, "Invalid interface name. Please use a valid network interface (e.g., eth0, wlan0, any)")
			return
		}
	}

	// 验证串口名称（对于 RS485 捕获）
	if req.Type == "rs485" {
		port := ""
		if val, ok := req.Config["port"].(string); ok {
			port = val
		}

		if port == "" {
			RespondBadRequest(c, "Serial port is required for RS485 capture")
			return
		}

		// 验证串口名称格式
		if !strings.HasPrefix(port, "/dev/tty") && !strings.HasPrefix(port, "COM") {
			RespondBadRequest(c, "Invalid serial port name. Must start with /dev/tty or COM")
			return
		}
	}

	// 验证 BPF 过滤器（仅对 IP 捕获）
	if req.Type == "ip" && req.Filter != "" {
		if !isValidBPFFilter(req.Filter) {
			RespondBadRequest(c, "Invalid BPF filter syntax. Please use valid BPF expressions (e.g., 'tcp port 80', 'host 192.168.1.1')")
			return
		}
	}

	// 创建会话记录
	now := time.Now()
	session := &models.CaptureSession{
		Name:      req.Name,
		Type:      req.Type,
		Status:    "running",
		StartTime: &now,
		Config:    models.JSON(req.Config),
	}

	if err := database.GetDB().Create(session).Error; err != nil {
		RespondInternalError(c, "Failed to create session")
		return
	}

	// 根据类型启动采集
	ctx, cancel := context.WithCancel(context.Background())
	h.mu.Lock()
	h.activeSessions[session.ID] = cancel
	h.mu.Unlock()

	switch req.Type {
	case "ip":
		go h.startIPCapture(ctx, session, req)
	case "can":
		go h.startCANCapture(ctx, session, req)
	case "rs485":
		go h.startRS485Capture(ctx, session, req)
	default:
		cancel()
		RespondBadRequest(c, "Invalid capture type")
		return
	}

	RespondSuccess(c, gin.H{
		"message":   "Capture started",
		"sessionId": session.ID,
	})
}

// startIPCapture 启动 IP 采集
func (h *CaptureHandler) startIPCapture(ctx context.Context, session *models.CaptureSession, req StartCaptureRequest) {
	iface := "eth0"
	if val, ok := req.Config["interface"].(string); ok {
		iface = val
	}

	ipCapture := capture.NewIPCapture(iface, 65536, true, 30, req.Filter, session.ID)

	if err := ipCapture.Start(ctx); err != nil {
		logger.GetLogger().Errorf("Failed to start IP capture: %v", err)
		return
	}

	// 创建批量写入器（每1000个包或每2秒刷新一次）
	batchWriter := database.NewBatchWriter(database.GetDB(), 1000, 2*time.Second)
	defer batchWriter.Close()

	// 统计信息
	var statsCount int64
	lastStatsUpdate := time.Now()

	// 处理数据包
	for pkt := range ipCapture.PacketChan {
		session.PacketCount++
		statsCount++

		// 处理 Payload：如果大于 1KB，保存到文件
		if len(pkt.Payload) > 1024 && h.payloadStorage != nil {
			payloadPath, payloadHash, err := h.payloadStorage.SaveWithHash(session.ID, pkt.Payload)
			if err != nil {
				logger.GetLogger().Errorf("Failed to save payload: %v", err)
			} else {
				pkt.PayloadPath = payloadPath
				pkt.PayloadHash = payloadHash
				pkt.Payload = nil // 清空内存中的 Payload
			}
		}

		// 自动分析数据包协议（如果有 Payload）
		if h.analyzer != nil && (len(pkt.Payload) > 0 || pkt.PayloadPath != "") {
			// 如果 Payload 在文件中，先加载
			payload := pkt.Payload
			if payload == nil && pkt.PayloadPath != "" && h.payloadStorage != nil {
				loadedPayload, err := h.payloadStorage.Load(pkt.PayloadPath)
				if err == nil {
					payload = loadedPayload
				}
			}

			// 创建临时数据包用于分析
			tempPkt := *pkt
			tempPkt.Payload = payload

			// 执行协议分析
			if analysisInfo, err := h.analyzer.Analyze(&tempPkt); err == nil {
				// 将分析结果保存到 AnalysisResult 字段
				pkt.AnalysisResult = models.JSON{
					"protocol":    analysisInfo.Protocol,
					"version":     analysisInfo.Version,
					"method":      analysisInfo.Method,
					"uri":         analysisInfo.URI,
					"status_code": analysisInfo.StatusCode,
					"summary":     analysisInfo.Summary,
					"fields":      analysisInfo.Fields,
				}

				// 检测异常
				if anomalies := h.analyzer.DetectAnomalies(analysisInfo); len(anomalies) > 0 {
					pkt.AnalysisResult["anomalies"] = anomalies
				}
			}
		}

		// 批量写入数据包
		if err := batchWriter.Write(pkt); err != nil {
			logger.GetLogger().Errorf("Failed to write packet: %v", err)
		}

		// 通过 WebSocket 推送实时数据（采样：每10个包推送一次）
		if statsCount%10 == 0 {
			h.wsHub.BroadcastToSession(session.ID, "packet", map[string]interface{}{
				"session_id": session.ID,
				"protocol":   pkt.Protocol,
				"src_addr":   pkt.SrcAddr,
				"dst_addr":   pkt.DstAddr,
				"length":     pkt.Length,
				"timestamp":  pkt.Timestamp,
			})
		}

		// 定期更新会话统计和推送统计信息（每5秒）
		if time.Since(lastStatsUpdate) >= 5*time.Second {
			database.GetDB().Model(session).Update("packet_count", session.PacketCount)

			// 推送统计信息
			h.wsHub.BroadcastToSession(session.ID, "stats", map[string]interface{}{
				"session_id":   session.ID,
				"packet_count": session.PacketCount,
				"rate":         float64(statsCount) / time.Since(lastStatsUpdate).Seconds(),
			})

			statsCount = 0
			lastStatsUpdate = time.Now()
		}
	}

	// 更新会话状态
	database.GetDB().Model(session).Updates(map[string]interface{}{
		"status":       "completed",
		"packet_count": session.PacketCount,
	})

	// 推送完成消息
	h.wsHub.BroadcastToSession(session.ID, "completed", map[string]interface{}{
		"session_id":   session.ID,
		"packet_count": session.PacketCount,
	})
}

// startCANCapture 启动 CAN 采集
func (h *CaptureHandler) startCANCapture(ctx context.Context, session *models.CaptureSession, req StartCaptureRequest) {
	iface := "can0"
	if val, ok := req.Config["interface"].(string); ok {
		iface = val
	}

	canCapture := capture.NewCANCapture(iface, session.ID)

	if err := canCapture.Start(ctx); err != nil {
		logger.GetLogger().Errorf("Failed to start CAN capture: %v", err)
		return
	}

	// 创建批量写入器
	batchWriter := database.NewBatchWriter(database.GetDB(), 1000, 2*time.Second)
	defer batchWriter.Close()

	var statsCount int64
	lastStatsUpdate := time.Now()

	for pkt := range canCapture.PacketChan {
		session.PacketCount++
		statsCount++

		// 自动分析 CAN 数据包（基本信息）
		if h.analyzer != nil && len(pkt.Payload) > 0 {
			// CAN 帧基本分析
			pkt.AnalysisResult = models.JSON{
				"protocol": "CAN",
				"summary":  fmt.Sprintf("CAN Frame: %s -> %s (%d bytes)", pkt.SrcAddr, pkt.DstAddr, pkt.Length),
			}
		}

		// CAN 数据包通常较小，直接保存
		if err := batchWriter.Write(pkt); err != nil {
			logger.GetLogger().Errorf("Failed to write packet: %v", err)
		}

		// WebSocket 推送
		if statsCount%10 == 0 {
			h.wsHub.BroadcastToSession(session.ID, "packet", map[string]interface{}{
				"session_id": session.ID,
				"protocol":   pkt.Protocol,
				"src_addr":   pkt.SrcAddr,
				"length":     pkt.Length,
				"timestamp":  pkt.Timestamp,
			})
		}

		// 定期更新统计
		if time.Since(lastStatsUpdate) >= 5*time.Second {
			database.GetDB().Model(session).Update("packet_count", session.PacketCount)
			h.wsHub.BroadcastToSession(session.ID, "stats", map[string]interface{}{
				"session_id":   session.ID,
				"packet_count": session.PacketCount,
				"rate":         float64(statsCount) / time.Since(lastStatsUpdate).Seconds(),
			})
			statsCount = 0
			lastStatsUpdate = time.Now()
		}
	}

	database.GetDB().Model(session).Updates(map[string]interface{}{
		"status":       "completed",
		"packet_count": session.PacketCount,
	})

	h.wsHub.BroadcastToSession(session.ID, "completed", map[string]interface{}{
		"session_id":   session.ID,
		"packet_count": session.PacketCount,
	})
}

// startRS485Capture 启动 RS485 采集
func (h *CaptureHandler) startRS485Capture(ctx context.Context, session *models.CaptureSession, req StartCaptureRequest) {
	port := "/dev/ttyUSB0"
	if val, ok := req.Config["port"].(string); ok {
		port = val
	}

	rs485Capture, err := capture.NewRS485Capture(port, 9600, 8, "N", 1, session.ID)
	if err != nil {
		logger.GetLogger().Errorf("Failed to create RS485 capture: %v", err)
		return
	}

	if err := rs485Capture.Start(ctx); err != nil {
		logger.GetLogger().Errorf("Failed to start RS485 capture: %v", err)
		return
	}

	// 创建批量写入器
	batchWriter := database.NewBatchWriter(database.GetDB(), 500, 2*time.Second)
	defer batchWriter.Close()

	var statsCount int64
	lastStatsUpdate := time.Now()

	for pkt := range rs485Capture.PacketChan {
		session.PacketCount++
		statsCount++

		// 自动分析 Modbus 协议
		if h.analyzer != nil && len(pkt.Payload) > 0 {
			if analysisInfo, err := h.analyzer.Analyze(pkt); err == nil {
				pkt.AnalysisResult = models.JSON{
					"protocol": analysisInfo.Protocol,
					"summary":  analysisInfo.Summary,
					"fields":   analysisInfo.Fields,
				}

				// 检测异常
				if anomalies := h.analyzer.DetectAnomalies(analysisInfo); len(anomalies) > 0 {
					pkt.AnalysisResult["anomalies"] = anomalies
				}
			}
		}

		if err := batchWriter.Write(pkt); err != nil {
			logger.GetLogger().Errorf("Failed to write packet: %v", err)
		}

		// WebSocket 推送
		if statsCount%5 == 0 {
			h.wsHub.BroadcastToSession(session.ID, "packet", map[string]interface{}{
				"session_id": session.ID,
				"protocol":   pkt.Protocol,
				"src_addr":   pkt.SrcAddr,
				"length":     pkt.Length,
				"timestamp":  pkt.Timestamp,
			})
		}

		// 定期更新统计
		if time.Since(lastStatsUpdate) >= 5*time.Second {
			database.GetDB().Model(session).Update("packet_count", session.PacketCount)
			h.wsHub.BroadcastToSession(session.ID, "stats", map[string]interface{}{
				"session_id":   session.ID,
				"packet_count": session.PacketCount,
			})
			statsCount = 0
			lastStatsUpdate = time.Now()
		}
	}

	database.GetDB().Model(session).Updates(map[string]interface{}{
		"status":       "completed",
		"packet_count": session.PacketCount,
	})

	h.wsHub.BroadcastToSession(session.ID, "completed", map[string]interface{}{
		"session_id":   session.ID,
		"packet_count": session.PacketCount,
	})
}

// StopCapture 停止采集
func (h *CaptureHandler) StopCapture(c *gin.Context) {
	sessionID := c.Query("session_id")
	id, err := strconv.ParseUint(sessionID, 10, 32)
	if err != nil {
		RespondBadRequest(c, "Invalid session ID")
		return
	}

	h.mu.Lock()
	cancel, exists := h.activeSessions[uint(id)]
	if exists {
		cancel()
		delete(h.activeSessions, uint(id))
	}
	h.mu.Unlock()

	if !exists {
		RespondNotFound(c, "Session not found")
		return
	}

	// 更新数据库状态和结束时间
	database.GetDB().Model(&models.CaptureSession{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":   "stopped",
		"end_time": time.Now(),
	})

	RespondSuccess(c, gin.H{"message": "Capture stopped"})
}

// ListSessions 列出会话（支持分页）
func (h *CaptureHandler) ListSessions(c *gin.Context) {
	var sessions []models.CaptureSession
	db := database.GetDB()

	// 获取分页参数
	params := GetPaginationParams(c)

	// 查询
	var total int64
	db.Model(&models.CaptureSession{}).Count(&total)
	db.Offset(params.GetOffset()).Limit(params.GetLimit()).Order("created_at DESC").Find(&sessions)

	// 计算元数据
	meta := CalculateMeta(total, params.Page, params.PageSize)

	// 返回标准响应
	RespondSuccessWithMeta(c, gin.H{"sessions": sessions}, meta)
}

// GetSession 获取会话详情
func (h *CaptureHandler) GetSession(c *gin.Context) {
	id := c.Param("id")
	var session models.CaptureSession

	if err := database.GetDB().First(&session, id).Error; err != nil {
		RespondNotFound(c, "Session not found")
		return
	}

	RespondSuccess(c, gin.H{"session": session})
}

// GetPackets 获取数据包（支持分页和过滤）
func (h *CaptureHandler) GetPackets(c *gin.Context) {
	sessionID := c.Param("id")

	// 获取分页参数
	params := GetPaginationParams(c)

	// 获取过滤参数
	protocol := c.Query("protocol")
	srcAddr := c.Query("src_addr")
	dstAddr := c.Query("dst_addr")

	// 验证输入参数
	// 验证协议参数
	if protocol != "" && !isValidProtocol(protocol) {
		RespondBadRequest(c, "Invalid protocol. Supported protocols: TCP, UDP, HTTP, DNS, ICMP, ARP, TLS, SSH, etc.")
		return
	}

	// 验证源地址
	if srcAddr != "" {
		// 允许部分 IP 地址用于搜索，但检查基本格式
		// 如果包含点号，验证是否为有效的 IP 地址或 IP 前缀
		if strings.Contains(srcAddr, ".") {
			// 尝试解析为完整 IP
			if net.ParseIP(srcAddr) == nil {
				// 如果不是完整 IP，检查是否为有效的 IP 前缀（如 "192.168"）
				parts := strings.Split(srcAddr, ".")
				if len(parts) > 4 {
					RespondBadRequest(c, "Invalid source IP address format")
					return
				}
				// 验证每个部分是否为有效数字
				for _, part := range parts {
					if part != "" {
						num, err := strconv.Atoi(part)
						if err != nil || num < 0 || num > 255 {
							RespondBadRequest(c, "Invalid source IP address format")
							return
						}
					}
				}
			}
		}

		// 防止 SQL 注入：检查是否包含危险字符
		if strings.ContainsAny(srcAddr, "';\"\\") {
			RespondBadRequest(c, "Invalid characters in source address")
			return
		}
	}

	// 验证目标地址（同源地址）
	if dstAddr != "" {
		if strings.Contains(dstAddr, ".") {
			if net.ParseIP(dstAddr) == nil {
				parts := strings.Split(dstAddr, ".")
				if len(parts) > 4 {
					RespondBadRequest(c, "Invalid destination IP address format")
					return
				}
				for _, part := range parts {
					if part != "" {
						num, err := strconv.Atoi(part)
						if err != nil || num < 0 || num > 255 {
							RespondBadRequest(c, "Invalid destination IP address format")
							return
						}
					}
				}
			}
		}

		if strings.ContainsAny(dstAddr, "';\"\\") {
			RespondBadRequest(c, "Invalid characters in destination address")
			return
		}
	}

	logger.GetLogger().Infof("GetPackets - sessionID: %s, protocol: %s, srcAddr: %s, dstAddr: %s",
		sessionID, protocol, srcAddr, dstAddr)

	var packets []models.Packet
	var total int64

	db := database.GetDB()

	// 构建查询条件
	query := db.Model(&models.Packet{}).Where("session_id = ?", sessionID)

	// 应用过滤条件（已验证的参数）
	if protocol != "" {
		query = query.Where("protocol = ?", protocol)
	}
	if srcAddr != "" {
		query = query.Where("src_addr LIKE ?", "%"+srcAddr+"%")
	}
	if dstAddr != "" {
		query = query.Where("dst_addr LIKE ?", "%"+dstAddr+"%")
	}

	// 计数
	query.Count(&total)

	logger.GetLogger().Infof("GetPackets - total count: %d", total)

	// 查询数据（需要重新构建查询，因为 Count 会影响查询）
	query = db.Model(&models.Packet{}).Where("session_id = ?", sessionID)
	if protocol != "" {
		query = query.Where("protocol = ?", protocol)
	}
	if srcAddr != "" {
		query = query.Where("src_addr LIKE ?", "%"+srcAddr+"%")
	}
	if dstAddr != "" {
		query = query.Where("dst_addr LIKE ?", "%"+dstAddr+"%")
	}
	query.Order("id DESC").Offset(params.GetOffset()).Limit(params.GetLimit()).Find(&packets)

	logger.GetLogger().Infof("GetPackets - returned %d packets", len(packets))

	// 确保payload数据正确返回给前端
	for i := range packets {
		// 如果payload在文件中，加载它
		if len(packets[i].Payload) == 0 && packets[i].PayloadPath != "" && h.payloadStorage != nil {
			if payload, err := h.payloadStorage.Load(packets[i].PayloadPath); err == nil {
				packets[i].Payload = payload
			}
		}
	}

	// 计算元数据
	meta := CalculateMeta(total, params.Page, params.PageSize)

	// 返回标准响应
	RespondSuccessWithMeta(c, gin.H{"packets": packets}, meta)
}

// GetInterfaces 获取可用网络接口
func (h *CaptureHandler) GetInterfaces(c *gin.Context) {
	interfaces, err := capture.GetAvailableInterfaces()
	if err != nil {
		RespondInternalError(c, err.Error())
		return
	}

	RespondSuccess(c, gin.H{"interfaces": interfaces})
}

// GetSerialPorts 获取可用串口列表
func (h *CaptureHandler) GetSerialPorts(c *gin.Context) {
	ports, err := capture.GetAvailableSerialPorts()
	if err != nil {
		RespondInternalError(c, err.Error())
		return
	}

	RespondSuccess(c, gin.H{"ports": ports})
}

// UploadPCAP 上传 PCAP 文件
func (h *CaptureHandler) UploadPCAP(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		RespondBadRequest(c, "No file uploaded")
		return
	}

	// 保存文件
	filename := fmt.Sprintf("./uploads/%d_%s", time.Now().Unix(), file.Filename)
	if err := c.SaveUploadedFile(file, filename); err != nil {
		RespondInternalError(c, "Failed to save file")
		return
	}

	// 创建会话
	session := &models.CaptureSession{
		Name:   file.Filename,
		Type:   "ip",
		Status: "completed",
	}
	database.GetDB().Create(session)

	// 解析 PCAP 文件
	go func() {
		packets, err := capture.LoadFromPCAP(filename, session.ID)
		if err != nil {
			logger.GetLogger().Errorf("Failed to load PCAP: %v", err)
			return
		}

		// 批量保存
		for _, pkt := range packets {
			database.GetDB().Create(pkt)
		}

		session.PacketCount = int64(len(packets))
		database.GetDB().Save(session)
	}()

	RespondSuccess(c, gin.H{
		"message":   "File uploaded successfully",
		"sessionId": session.ID,
	})
}

// HandleWebSocket WebSocket 处理
func (h *CaptureHandler) HandleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.GetLogger().Errorf("WebSocket upgrade failed: %v", err)
		return
	}
	// 创建 WebSocket 客户端
	client := wsHub.NewClient(h.wsHub, conn)
	h.wsHub.RegisterClient(client)

	// 启动读写协程
	go client.WritePump()
	go client.ReadPump()
}

// GetPayload 获取数据包 Payload
func (h *CaptureHandler) GetPayload(c *gin.Context) {
	packetID := c.Param("id")

	var packet models.Packet
	if err := database.GetDB().First(&packet, packetID).Error; err != nil {
		RespondNotFound(c, "Packet not found")
		return
	}

	// 如果 Payload 在数据库中
	if len(packet.Payload) > 0 {
		c.Data(200, "application/octet-stream", packet.Payload)
		return
	}

	// 如果 Payload 在文件中
	if packet.PayloadPath != "" && h.payloadStorage != nil {
		payload, err := h.payloadStorage.Load(packet.PayloadPath)
		if err != nil {
			RespondInternalError(c, "Failed to load payload")
			return
		}
		c.Data(200, "application/octet-stream", payload)
		return
	}

	RespondNotFound(c, "Payload not found")
}

// DeleteSession 删除会话
func (h *CaptureHandler) DeleteSession(c *gin.Context) {
	sessionID := c.Param("id")

	// 检查会话是否存在
	var session models.CaptureSession
	if err := database.GetDB().First(&session, sessionID).Error; err != nil {
		RespondNotFound(c, "Session not found")
		return
	}

	// 检查会话是否正在运行
	h.mu.Lock()
	id, _ := strconv.ParseUint(sessionID, 10, 32)
	if _, exists := h.activeSessions[uint(id)]; exists {
		h.mu.Unlock()
		RespondBadRequest(c, "Cannot delete running session")
		return
	}
	h.mu.Unlock()

	// 删除相关数据包
	database.GetDB().Where("session_id = ?", sessionID).Delete(&models.Packet{})

	// 删除会话
	database.GetDB().Delete(&session)

	RespondSuccess(c, gin.H{"message": "Session deleted successfully"})
}
