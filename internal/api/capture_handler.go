package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"netsecanalyzer/internal/analyzer"
	"netsecanalyzer/internal/capture"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/export"
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

// CaptureHandler 数据采集处理器
type CaptureHandler struct {
	activeSessions map[uint]context.CancelFunc
	payloadStorage *storage.PayloadStorage
	wsHub          *wsHub.Hub
	exporter       *export.Exporter
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

	// 创建导出器
	exporter := export.NewExporter("./data/exports")

	// 创建协议分析器
	protocolAnalyzer := analyzer.NewAnalyzer()

	return &CaptureHandler{
		activeSessions: make(map[uint]context.CancelFunc),
		payloadStorage: payloadStorage,
		exporter:       exporter,
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
		c.JSON(400, gin.H{"error": err.Error()})
		return
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
		c.JSON(500, gin.H{"error": "Failed to create session"})
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
		c.JSON(400, gin.H{"error": "Invalid capture type"})
		return
	}

	c.JSON(200, gin.H{
		"message":    "Capture started",
		"session_id": session.ID,
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
		c.JSON(400, gin.H{"error": "Invalid session ID"})
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
		c.JSON(404, gin.H{"error": "Session not found"})
		return
	}

	// 更新数据库状态
	database.GetDB().Model(&models.CaptureSession{}).Where("id = ?", id).Update("status", "stopped")

	c.JSON(200, gin.H{"message": "Capture stopped"})
}

// ListSessions 列出会话
func (h *CaptureHandler) ListSessions(c *gin.Context) {
	var sessions []models.CaptureSession
	db := database.GetDB()

	// 分页参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	offset := (page - 1) * pageSize

	// 查询
	var total int64
	db.Model(&models.CaptureSession{}).Count(&total)
	db.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&sessions)

	c.JSON(200, gin.H{
		"data":      sessions,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetSession 获取会话详情
func (h *CaptureHandler) GetSession(c *gin.Context) {
	id := c.Param("id")
	var session models.CaptureSession

	if err := database.GetDB().First(&session, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Session not found"})
		return
	}

	c.JSON(200, session)
}

// GetPackets 获取数据包
func (h *CaptureHandler) GetPackets(c *gin.Context) {
	sessionID := c.Param("id")

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	offset := (page - 1) * pageSize

	// 获取过滤参数
	protocol := c.Query("protocol")
	srcAddr := c.Query("src_addr")
	dstAddr := c.Query("dst_addr")

	logger.GetLogger().Infof("GetPackets - sessionID: %s, protocol: %s, srcAddr: %s, dstAddr: %s",
		sessionID, protocol, srcAddr, dstAddr)

	var packets []models.Packet
	var total int64

	db := database.GetDB()

	// 构建查询条件
	query := db.Model(&models.Packet{}).Where("session_id = ?", sessionID)

	// 应用过滤条件
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
	query.Order("id DESC").Offset(offset).Limit(pageSize).Find(&packets)

	logger.GetLogger().Infof("GetPackets - returned %d packets", len(packets))

	c.JSON(200, gin.H{
		"data":      packets,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetInterfaces 获取可用网络接口
func (h *CaptureHandler) GetInterfaces(c *gin.Context) {
	interfaces, err := capture.GetAvailableInterfaces()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"interfaces": interfaces})
}

// GetSerialPorts 获取可用串口列表
func (h *CaptureHandler) GetSerialPorts(c *gin.Context) {
	ports, err := capture.GetAvailableSerialPorts()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"ports": ports})
}

// UploadPCAP 上传 PCAP 文件
func (h *CaptureHandler) UploadPCAP(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "No file uploaded"})
		return
	}

	// 保存文件
	filename := fmt.Sprintf("./uploads/%d_%s", time.Now().Unix(), file.Filename)
	if err := c.SaveUploadedFile(file, filename); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save file"})
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

	c.JSON(200, gin.H{
		"message":    "File uploaded successfully",
		"session_id": session.ID,
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
		c.JSON(404, gin.H{"error": "Packet not found"})
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
			c.JSON(500, gin.H{"error": "Failed to load payload"})
			return
		}
		c.Data(200, "application/octet-stream", payload)
		return
	}

	c.JSON(404, gin.H{"error": "Payload not found"})
}

// ExportSession 导出会话数据
func (h *CaptureHandler) ExportSession(c *gin.Context) {
	sessionID := c.Param("id")
	format := c.Query("format") // pcap, csv, json

	if format == "" {
		format = "pcap"
	}

	// 获取会话信息
	var session models.CaptureSession
	if err := database.GetDB().First(&session, sessionID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Session not found"})
		return
	}

	// 获取所有数据包
	var packets []models.Packet
	database.GetDB().Where("session_id = ?", sessionID).Find(&packets)

	if len(packets) == 0 {
		c.JSON(404, gin.H{"error": "No packets found"})
		return
	}

	// 转换为指针切片
	packetPtrs := make([]*models.Packet, len(packets))
	for i := range packets {
		packetPtrs[i] = &packets[i]
	}

	var filepath string
	var err error

	// 根据格式导出
	switch format {
	case "pcap":
		filepath, err = h.exporter.ExportSessionToPCAP(&session, packetPtrs)
	case "csv":
		filepath, err = h.exporter.ExportSessionToCSV(&session, packetPtrs)
	case "json":
		filepath, err = h.exporter.ExportSessionToJSON(&session, packetPtrs)
	default:
		c.JSON(400, gin.H{"error": "Invalid format. Supported: pcap, csv, json"})
		return
	}

	if err != nil {
		logger.GetLogger().Errorf("Failed to export session: %v", err)
		c.JSON(500, gin.H{"error": "Export failed"})
		return
	}

	// 返回文件
	c.FileAttachment(filepath, filepath[len("./data/exports/"):])
}

// DeleteSession 删除会话
func (h *CaptureHandler) DeleteSession(c *gin.Context) {
	sessionID := c.Param("id")

	// 检查会话是否存在
	var session models.CaptureSession
	if err := database.GetDB().First(&session, sessionID).Error; err != nil {
		c.JSON(404, gin.H{"error": "Session not found"})
		return
	}

	// 检查会话是否正在运行
	h.mu.Lock()
	id, _ := strconv.ParseUint(sessionID, 10, 32)
	if _, exists := h.activeSessions[uint(id)]; exists {
		h.mu.Unlock()
		c.JSON(400, gin.H{"error": "Cannot delete running session"})
		return
	}
	h.mu.Unlock()

	// 删除相关数据包
	database.GetDB().Where("session_id = ?", sessionID).Delete(&models.Packet{})

	// 删除会话
	database.GetDB().Delete(&session)

	c.JSON(200, gin.H{"message": "Session deleted successfully"})
}
