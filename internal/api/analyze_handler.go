package api

import (
	"netsecanalyzer/internal/analyzer"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"

	"github.com/gin-gonic/gin"
)

// AnalyzeHandler 协议分析处理器
type AnalyzeHandler struct {
	analyzer *analyzer.Analyzer
}

// NewAnalyzeHandler 创建分析处理器
func NewAnalyzeHandler(a *analyzer.Analyzer) *AnalyzeHandler {
	return &AnalyzeHandler{analyzer: a}
}

// ParsePacket 解析数据包
func (h *AnalyzeHandler) ParsePacket(c *gin.Context) {
	var pkt models.Packet
	if err := c.ShouldBindJSON(&pkt); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	info, err := h.analyzer.Analyze(&pkt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, info)
}

// GetProtocols 获取支持的协议
func (h *AnalyzeHandler) GetProtocols(c *gin.Context) {
	protocols := h.analyzer.GetSupportedProtocols()
	c.JSON(200, gin.H{"protocols": protocols})
}

// GetStatistics 获取统计信息
func (h *AnalyzeHandler) GetStatistics(c *gin.Context) {
	var req struct {
		SessionID uint `json:"session_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var packets []models.Packet
	database.GetDB().Where("session_id = ?", req.SessionID).Find(&packets)

	// 转换为指针切片
	packetPtrs := make([]*models.Packet, len(packets))
	for i := range packets {
		packetPtrs[i] = &packets[i]
	}

	stats := analyzer.GenerateStatistics(packetPtrs)
	c.JSON(200, stats)
}
