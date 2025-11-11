package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"netsecanalyzer/internal/capture"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"

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
	mu             sync.Mutex
}

// NewCaptureHandler 创建采集处理器
func NewCaptureHandler() *CaptureHandler {
	return &CaptureHandler{
		activeSessions: make(map[uint]context.CancelFunc),
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

	// 处理数据包
	for pkt := range ipCapture.PacketChan {
		session.PacketCount++
		// 保存到数据库（批量保存以提高性能）
		if err := database.GetDB().Create(pkt).Error; err != nil {
			logger.GetLogger().Errorf("Failed to save packet: %v", err)
		}

		// 定期更新会话统计
		if session.PacketCount%100 == 0 {
			database.GetDB().Model(session).Update("packet_count", session.PacketCount)
		}
	}

	// 更新会话状态
	database.GetDB().Model(session).Updates(map[string]interface{}{
		"status":       "completed",
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

	for pkt := range canCapture.PacketChan {
		session.PacketCount++
		if err := database.GetDB().Create(pkt).Error; err != nil {
			logger.GetLogger().Errorf("Failed to save packet: %v", err)
		}

		if session.PacketCount%100 == 0 {
			database.GetDB().Model(session).Update("packet_count", session.PacketCount)
		}
	}

	database.GetDB().Model(session).Updates(map[string]interface{}{
		"status":       "completed",
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

	for pkt := range rs485Capture.PacketChan {
		session.PacketCount++
		if err := database.GetDB().Create(pkt).Error; err != nil {
			logger.GetLogger().Errorf("Failed to save packet: %v", err)
		}
	}

	database.GetDB().Model(session).Update("status", "completed")
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

	var packets []models.Packet
	var total int64

	db := database.GetDB()
	db.Model(&models.Packet{}).Where("session_id = ?", sessionID).Count(&total)
	db.Where("session_id = ?", sessionID).Offset(offset).Limit(pageSize).Find(&packets)

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
	defer conn.Close()

	// 实现实时数据推送
	// 这里简化处理，实际应该根据客户端请求推送对应会话的数据
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
		// 推送数据包
	}
}
