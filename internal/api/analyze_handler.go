package api

import (
	"fmt"

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

// GetPacketAnalysis 获取单个数据包的分析结果
func (h *AnalyzeHandler) GetPacketAnalysis(c *gin.Context) {
	id := c.Param("id")

	var packet models.Packet
	if err := database.GetDB().First(&packet, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Packet not found"})
		return
	}

	// 如果已有分析结果，直接返回
	if packet.AnalysisResult != nil && len(packet.AnalysisResult) > 0 {
		c.JSON(200, gin.H{
			"packet_id": packet.ID,
			"analysis":  packet.AnalysisResult,
		})
		return
	}

	// 如果没有分析结果，执行分析
	info, err := h.analyzer.Analyze(&packet)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 保存分析结果
	packet.AnalysisResult = models.JSON{
		"protocol":    info.Protocol,
		"version":     info.Version,
		"method":      info.Method,
		"uri":         info.URI,
		"status_code": info.StatusCode,
		"summary":     info.Summary,
		"fields":      info.Fields,
	}

	// 检测异常
	if anomalies := h.analyzer.DetectAnomalies(info); len(anomalies) > 0 {
		packet.AnalysisResult["anomalies"] = anomalies
	}

	database.GetDB().Save(&packet)

	c.JSON(200, gin.H{
		"packet_id": packet.ID,
		"analysis":  packet.AnalysisResult,
	})
}

// GetSessionAnalysis 获取会话所有数据包的分析结果
func (h *AnalyzeHandler) GetSessionAnalysis(c *gin.Context) {
	sessionID := c.Param("id")

	var packets []models.Packet
	query := database.GetDB().Where("session_id = ?", sessionID)

	// 支持分页
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "100")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)

	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 || pageSizeInt > 1000 {
		pageSizeInt = 100
	}

	offset := (pageInt - 1) * pageSizeInt

	var total int64
	query.Model(&models.Packet{}).Count(&total)

	query.Offset(offset).Limit(pageSizeInt).Find(&packets)

	// 提取分析结果
	results := make([]map[string]interface{}, 0, len(packets))
	for _, pkt := range packets {
		if pkt.AnalysisResult != nil && len(pkt.AnalysisResult) > 0 {
			results = append(results, map[string]interface{}{
				"packet_id": pkt.ID,
				"timestamp": pkt.Timestamp,
				"src_addr":  pkt.SrcAddr,
				"dst_addr":  pkt.DstAddr,
				"analysis":  pkt.AnalysisResult,
			})
		}
	}

	c.JSON(200, gin.H{
		"session_id": sessionID,
		"total":      total,
		"page":       pageInt,
		"page_size":  pageSizeInt,
		"results":    results,
	})
}

// GetSessionAnomalies 获取会话的异常检测结果
func (h *AnalyzeHandler) GetSessionAnomalies(c *gin.Context) {
	sessionID := c.Param("id")

	var packets []models.Packet
	database.GetDB().Where("session_id = ? AND JSON_EXTRACT(analysis_result, '$.anomalies') IS NOT NULL", sessionID).Find(&packets)

	anomalies := make([]map[string]interface{}, 0)
	for _, pkt := range packets {
		if pkt.AnalysisResult != nil {
			if anomalyList, ok := pkt.AnalysisResult["anomalies"]; ok {
				anomalies = append(anomalies, map[string]interface{}{
					"packet_id": pkt.ID,
					"timestamp": pkt.Timestamp,
					"src_addr":  pkt.SrcAddr,
					"dst_addr":  pkt.DstAddr,
					"protocol":  pkt.AnalysisResult["protocol"],
					"anomalies": anomalyList,
				})
			}
		}
	}

	c.JSON(200, gin.H{
		"session_id": sessionID,
		"count":      len(anomalies),
		"anomalies":  anomalies,
	})
}

// ReanalyzeSession 重新分析会话的所有数据包
func (h *AnalyzeHandler) ReanalyzeSession(c *gin.Context) {
	sessionID := c.Param("id")

	var packets []models.Packet
	database.GetDB().Where("session_id = ?", sessionID).Find(&packets)

	if len(packets) == 0 {
		c.JSON(404, gin.H{"error": "No packets found for this session"})
		return
	}

	// 批量分析
	packetPtrs := make([]*models.Packet, len(packets))
	for i := range packets {
		packetPtrs[i] = &packets[i]
	}

	results := h.analyzer.AnalyzeBatch(packetPtrs, 10)

	// 保存分析结果
	for i, info := range results {
		if info != nil {
			packets[i].AnalysisResult = models.JSON{
				"protocol":    info.Protocol,
				"version":     info.Version,
				"method":      info.Method,
				"uri":         info.URI,
				"status_code": info.StatusCode,
				"summary":     info.Summary,
				"fields":      info.Fields,
			}

			// 检测异常
			if anomalies := h.analyzer.DetectAnomalies(info); len(anomalies) > 0 {
				packets[i].AnalysisResult["anomalies"] = anomalies
			}

			database.GetDB().Save(&packets[i])
		}
	}

	c.JSON(200, gin.H{
		"session_id":     sessionID,
		"analyzed_count": len(packets),
		"message":        "Reanalysis completed",
	})
}
