package api

import (
	"context"
	"netsecanalyzer/internal/scanner"
	"netsecanalyzer/pkg/utils"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ScanHandler 扫描处理器
type ScanHandler struct {
	scanner *scanner.Scanner
}

// NewScanHandler 创建扫描处理器
func NewScanHandler(s *scanner.Scanner) *ScanHandler {
	return &ScanHandler{scanner: s}
}

// StartScan 启动扫描
func (h *ScanHandler) StartScan(c *gin.Context) {
	var req struct {
		Target    string `json:"target" binding:"required"`
		PortRange string `json:"port_range"`
		ScanType  string `json:"scan_type" binding:"required,oneof=port service vuln"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 解析端口范围
	portRange := req.PortRange
	if portRange == "" {
		portRange = "1-1024"
	}

	ports, err := utils.ParsePortRange(portRange)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid port range"})
		return
	}

	// 异步执行扫描
	go func() {
		ctx := context.Background()
		result, err := h.scanner.ScanPorts(ctx, req.Target, ports)
		if err != nil {
			return
		}

		// 如果需要服务识别
		if req.ScanType == "service" || req.ScanType == "vuln" {
			openPorts := make([]int, len(result.OpenPorts))
			for i, p := range result.OpenPorts {
				openPorts[i] = p.Port
			}
			services, _ := h.scanner.ScanServices(ctx, req.Target, openPorts)
			result.Services = services

			// 如果需要漏洞检测
			if req.ScanType == "vuln" {
				vulns, _ := h.scanner.DetectVulnerabilities(ctx, req.Target, services)
				result.Vulnerabilities = vulns
			}
		}
	}()

	c.JSON(200, gin.H{"message": "Scan started"})
}

// ListTasks 列出扫描任务
func (h *ScanHandler) ListTasks(c *gin.Context) {
	c.JSON(200, gin.H{"tasks": []interface{}{}})
}

// GetTask 获取任务详情
func (h *ScanHandler) GetTask(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	c.JSON(200, gin.H{"id": id})
}

// HandleWebSocket WebSocket 处理
func (h *ScanHandler) HandleWebSocket(c *gin.Context) {
	// 实现 WebSocket 连接
}
