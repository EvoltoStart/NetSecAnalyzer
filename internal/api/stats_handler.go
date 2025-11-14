package api

import (
	"fmt"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"
	"time"

	"github.com/gin-gonic/gin"
)

// StatsHandler 统计数据处理器
type StatsHandler struct{}

// NewStatsHandler 创建统计处理器
func NewStatsHandler() *StatsHandler {
	return &StatsHandler{}
}

// GetOverviewStats 获取总览统计
func (h *StatsHandler) GetOverviewStats(c *gin.Context) {
	db := database.GetDB()

	var stats struct {
		ActiveSessions  int64 `json:"activeSessions"`
		TotalPackets    int64 `json:"totalPackets"`
		Vulnerabilities int64 `json:"vulnerabilities"`
		Attacks         int64 `json:"attacks"`
	}

	// 活动会话数
	db.Model(&models.CaptureSession{}).Where("status = ?", "running").Count(&stats.ActiveSessions)

	// 总数据包数
	db.Model(&models.Packet{}).Count(&stats.TotalPackets)

	// 漏洞数量
	db.Model(&models.Vulnerability{}).Count(&stats.Vulnerabilities)

	// 攻击测试数量（使用 AttackTask 表）
	db.Model(&models.AttackTask{}).Count(&stats.Attacks)

	RespondSuccess(c, stats)
}

// GetProtocolDistribution 获取协议分布
func (h *StatsHandler) GetProtocolDistribution(c *gin.Context) {
	db := database.GetDB()

	var protocolStats []struct {
		Protocol string `json:"protocol"`
		Count    int64  `json:"count"`
	}

	// 从 packets 表统计协议分布
	db.Model(&models.Packet{}).
		Select("protocol, COUNT(*) as count").
		Group("protocol").
		Order("count DESC").
		Limit(10).
		Find(&protocolStats)

	// 转换为前端需要的格式
	result := make([]map[string]interface{}, 0)
	for _, stat := range protocolStats {
		if stat.Protocol == "" {
			continue
		}
		result = append(result, map[string]interface{}{
			"name":  stat.Protocol,
			"value": stat.Count,
		})
	}

	RespondSuccess(c, gin.H{"protocols": result})
}

// GetTrafficTrend 获取流量趋势
func (h *StatsHandler) GetTrafficTrend(c *gin.Context) {
	db := database.GetDB()

	// 获取最近 24 小时的数据，按小时分组
	var trendData []struct {
		Hour  int   `json:"hour"`
		Count int64 `json:"count"`
	}

	now := time.Now()
	startTime := now.Add(-24 * time.Hour)

	// 根据数据库类型选择不同的时间函数
	hourExpr := "HOUR(created_at)"
	if db.Dialector.Name() == "sqlite" {
		hourExpr = "strftime('%H', created_at)"
	}

	db.Model(&models.Packet{}).
		Select(hourExpr+" as hour, COUNT(*) as count").
		Where("created_at >= ?", startTime).
		Group(hourExpr).
		Order("hour").
		Find(&trendData)

	// 构建完整的 24 小时数据（填充空缺）
	hourMap := make(map[int]int64)
	for _, data := range trendData {
		hourMap[data.Hour] = data.Count
	}

	times := make([]string, 0)
	counts := make([]int64, 0)
	for i := 0; i < 24; i++ {
		hour := (now.Hour() - 23 + i + 24) % 24
		times = append(times, formatHour(hour))
		counts = append(counts, hourMap[hour])
	}

	RespondSuccess(c, gin.H{
		"times":  times,
		"counts": counts,
	})
}

// GetSessionProtocolStats 获取指定会话的协议统计
func (h *StatsHandler) GetSessionProtocolStats(c *gin.Context) {
	sessionID := c.Param("id")
	db := database.GetDB()

	var protocolStats []models.ProtocolStat
	db.Where("session_id = ?", sessionID).Find(&protocolStats)

	RespondSuccess(c, gin.H{"protocolStats": protocolStats})
}

// GetRecentSessions 获取最近的会话
func (h *StatsHandler) GetRecentSessions(c *gin.Context) {
	limit := c.DefaultQuery("limit", "10")
	db := database.GetDB()

	var sessions []models.CaptureSession
	db.Order("created_at DESC").Limit(parseInt(limit, 10)).Find(&sessions)

	RespondSuccess(c, gin.H{"sessions": sessions})
}

// GetRecentVulnerabilities 获取最近发现的漏洞
func (h *StatsHandler) GetRecentVulnerabilities(c *gin.Context) {
	limit := c.DefaultQuery("limit", "10")
	db := database.GetDB()

	var vulns []models.Vulnerability
	db.Order("discovered_at DESC").Limit(parseInt(limit, 10)).Find(&vulns)

	RespondSuccess(c, gin.H{"vulnerabilities": vulns})
}

// formatHour 格式化小时
func formatHour(hour int) string {
	return formatTime(hour, 0)
}

// formatTime 格式化时间
func formatTime(hour, minute int) string {
	return padZero(hour) + ":" + padZero(minute)
}

// padZero 补零
func padZero(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// parseInt 解析整数
func parseInt(s string, defaultValue int) int {
	var result int
	if _, err := fmt.Sscanf(s, "%d", &result); err != nil {
		return defaultValue
	}
	return result
}
