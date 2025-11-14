package api

import (
	"context"
	"fmt"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/export"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/internal/scanner"
	"netsecanalyzer/pkg/logger"
	"netsecanalyzer/pkg/utils"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ScanHandler 扫描处理器
type ScanHandler struct {
	scanner  *scanner.Scanner
	exporter *export.Exporter
}

// NewScanHandler 创建扫描处理器
func NewScanHandler(s *scanner.Scanner) *ScanHandler {
	return &ScanHandler{
		scanner:  s,
		exporter: export.NewExporter("./data/exports"),
	}
}

// StartScan 启动扫描
func (h *ScanHandler) StartScan(c *gin.Context) {
	var req struct {
		Target      string                 `json:"target" binding:"required"`
		PortRange   string                 `json:"port_range"`
		ScanType    string                 `json:"scan_type" binding:"required,oneof=port service vuln can rs485"`
		NetworkType string                 `json:"network_type"` // ip, can, rs485
		Config      map[string]interface{} `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	// 根据网络类型选择扫描方式
	networkType := req.NetworkType
	if networkType == "" {
		networkType = "ip" // 默认 IP 网络
	}

	// 创建扫描任务
	now := time.Now()
	task := &models.ScanTask{
		Name:        req.Target,
		Target:      req.Target,
		ScanType:    req.ScanType,
		Status:      "running",
		Progress:    0,
		NetworkType: networkType,
		StartTime:   &now,
	}
	database.GetDB().Create(task)

	logger.GetLogger().Infof("Created scan task %d: target=%s, type=%s, network=%s",
		task.ID, req.Target, req.ScanType, networkType)

	// 异步执行扫描
	go func() {
		ctx := context.Background()

		switch networkType {
		case "can":
			h.scanCANBus(ctx, task, req)
		case "rs485":
			h.scanRS485Bus(ctx, task, req)
		default:
			h.scanIPNetwork(ctx, task, req)
		}
	}()

	RespondSuccess(c, gin.H{
		"message": "Scan started",
		"taskId":  task.ID,
	})
}

// scanIPNetwork 扫描 IP 网络
func (h *ScanHandler) scanIPNetwork(ctx context.Context, task *models.ScanTask, req struct {
	Target      string                 `json:"target" binding:"required"`
	PortRange   string                 `json:"port_range"`
	ScanType    string                 `json:"scan_type" binding:"required,oneof=port service vuln can rs485"`
	NetworkType string                 `json:"network_type"`
	Config      map[string]interface{} `json:"config"`
}) {
	// 解析端口范围
	portRange := req.PortRange
	if portRange == "" {
		portRange = "1-1024"
	}

	ports, err := utils.ParsePortRange(portRange)
	if err != nil {
		task.Status = "failed"
		task.Error = "Invalid port range"
		database.GetDB().Save(task)
		return
	}

	// 执行端口扫描
	result, err := h.scanner.ScanPorts(ctx, req.Target, ports)
	if err != nil {
		endTime := time.Now()
		task.Status = "failed"
		task.Error = err.Error()
		task.EndTime = &endTime
		database.GetDB().Save(task)
		logger.GetLogger().Errorf("Port scan failed for task %d: %v", task.ID, err)
		return
	}

	logger.GetLogger().Infof("Port scan completed for task %d: found %d open ports", task.ID, len(result.OpenPorts))

	// 保存端口扫描结果（包含服务识别信息）
	for _, port := range result.OpenPorts {
		scanResult := &models.ScanResult{
			TaskID:     task.ID,
			ResultType: "port",
			Target:     req.Target,
			Port:       port.Port,
			Protocol:   port.Protocol,
			Service:    port.Service,
			State:      port.State,
			Version:    port.Version,
			Banner:     port.Banner,
		}
		if err := database.GetDB().Create(scanResult).Error; err != nil {
			logger.GetLogger().Errorf("Failed to save scan result for task %d, port %d: %v", task.ID, port.Port, err)
		} else {
			logger.GetLogger().Debugf("Saved scan result for task %d, port %d (service: %s, version: %s)",
				task.ID, port.Port, port.Service, port.Version)
		}
	}

	logger.GetLogger().Infof("Saved %d scan results for task %d", len(result.OpenPorts), task.ID)

	task.Progress = 60
	database.GetDB().Save(task)

	// 执行基础漏洞检测（检查常见安全问题）
	if len(result.OpenPorts) > 0 {
		logger.GetLogger().Infof("Starting vulnerability detection for task %d", task.ID)

		// 将 PortInfo 转换为 ServiceInfo
		var services []scanner.ServiceInfo
		for _, port := range result.OpenPorts {
			services = append(services, scanner.ServiceInfo{
				Port:    port.Port,
				Name:    port.Service,
				Version: port.Version,
				Banner:  port.Banner,
			})
		}

		// 执行漏洞检测
		vulns, err := h.scanner.DetectVulnerabilities(ctx, req.Target, services)
		if err == nil && len(vulns) > 0 {
			logger.GetLogger().Infof("Found %d vulnerabilities for task %d", len(vulns), task.ID)

			// 保存漏洞检测结果
			for _, vuln := range vulns {
				// 从 Target 中提取端口号
				port := 0
				if strings.Contains(vuln.Target, ":") {
					parts := strings.Split(vuln.Target, ":")
					if len(parts) == 2 {
						fmt.Sscanf(parts[1], "%d", &port)
					}
				}

				scanResult := &models.ScanResult{
					TaskID:      task.ID,
					ResultType:  "vulnerability",
					Target:      vuln.Target,
					Port:        port,
					Severity:    vuln.Severity,
					Title:       vuln.Title,
					Description: vuln.Description,
					Solution:    vuln.Solution,
					VulnType:    vuln.VulnType,
					CVE:         vuln.CVEID,
				}
				if err := database.GetDB().Create(scanResult).Error; err != nil {
					logger.GetLogger().Errorf("Failed to save vulnerability for task %d: %v", task.ID, err)
				} else {
					logger.GetLogger().Debugf("Saved vulnerability for task %d: %s", task.ID, vuln.Title)
				}
			}
		}

		task.Progress = 90
		database.GetDB().Save(task)
	}

	// 如果需要深度服务识别（保留原有逻辑用于未来扩展）
	if req.ScanType == "service" || req.ScanType == "vuln" {
		openPorts := make([]int, len(result.OpenPorts))
		for i, p := range result.OpenPorts {
			openPorts[i] = p.Port
		}
		services, _ := h.scanner.ScanServices(ctx, req.Target, openPorts)

		// 保存服务识别结果
		for _, svc := range services {
			scanResult := &models.ScanResult{
				TaskID:     task.ID,
				ResultType: "service",
				Target:     req.Target,
				Port:       svc.Port,
				Service:    svc.Name,
				Version:    svc.Version,
				Banner:     svc.Banner,
			}
			database.GetDB().Create(scanResult)
		}

		task.Progress = 75
		database.GetDB().Save(task)

		// 如果需要漏洞检测
		if req.ScanType == "vuln" {
			vulns, _ := h.scanner.DetectVulnerabilities(ctx, req.Target, services)

			// 保存漏洞检测结果
			for _, vuln := range vulns {
				scanResult := &models.ScanResult{
					TaskID:      task.ID,
					ResultType:  "vulnerability",
					Target:      vuln.Target,
					Severity:    vuln.Severity,
					Title:       vuln.Title,
					Description: vuln.Description,
					CVE:         vuln.CVEID,
					VulnType:    vuln.VulnType,
				}
				database.GetDB().Create(scanResult)
			}
		}
	}

	endTime := time.Now()
	task.Status = "completed"
	task.Progress = 100
	task.EndTime = &endTime
	database.GetDB().Save(task)

	duration := endTime.Sub(*task.StartTime)
	logger.GetLogger().Infof("IP scan task %d completed in %s", task.ID, duration)
}

// scanCANBus 扫描 CAN 总线
func (h *ScanHandler) scanCANBus(ctx context.Context, task *models.ScanTask, req struct {
	Target      string                 `json:"target" binding:"required"`
	PortRange   string                 `json:"port_range"`
	ScanType    string                 `json:"scan_type" binding:"required,oneof=port service vuln can rs485"`
	NetworkType string                 `json:"network_type"`
	Config      map[string]interface{} `json:"config"`
}) {
	// 获取 CAN 接口
	iface := "can0"
	if val, ok := req.Config["interface"].(string); ok {
		iface = val
	}

	// 设置 CAN 扫描器
	h.scanner.SetCANScanner(iface)

	// 获取扫描时长
	duration := 30 * time.Second
	if val, ok := req.Config["duration"].(float64); ok {
		duration = time.Duration(val) * time.Second
	}

	// 执行 CAN 总线扫描
	result, err := h.scanner.CANScanner.ScanCANBus(ctx, duration)
	if err != nil {
		task.Status = "failed"
		task.Error = err.Error()
		database.GetDB().Save(task)
		logger.GetLogger().Errorf("CAN scan failed: %v", err)
		return
	}

	// 保存 CAN ID 结果
	for _, idInfo := range result.ActiveIDs {
		scanResult := &models.ScanResult{
			TaskID:      task.ID,
			ResultType:  "can_id",
			Target:      iface,
			Description: fmt.Sprintf("CAN ID: %s, Frames: %d, Freq: %.2f Hz", idInfo.IDHex, idInfo.FrameCount, idInfo.Frequency),
			Details: models.JSON{
				"can_id":      idInfo.ID,
				"id_hex":      idInfo.IDHex,
				"frame_count": idInfo.FrameCount,
				"frequency":   idInfo.Frequency,
				"is_extended": idInfo.IsExtended,
				"is_rtr":      idInfo.IsRTR,
			},
		}
		database.GetDB().Create(scanResult)
	}

	task.Progress = 70
	database.GetDB().Save(task)

	// 保存异常检测结果
	for _, anomaly := range result.Anomalies {
		scanResult := &models.ScanResult{
			TaskID:      task.ID,
			ResultType:  "vulnerability",
			Target:      iface,
			Severity:    anomaly.Severity,
			Title:       anomaly.Type,
			Description: anomaly.Description,
			Details: models.JSON{
				"can_id":    anomaly.CANID,
				"timestamp": anomaly.Timestamp,
			},
		}
		database.GetDB().Create(scanResult)
	}

	task.Progress = 90
	database.GetDB().Save(task)

	// 保存拓扑节点
	for _, node := range result.TopologyNodes {
		scanResult := &models.ScanResult{
			TaskID:      task.ID,
			ResultType:  "topology",
			Target:      iface,
			Description: node.Description,
			Details: models.JSON{
				"node_id":     node.NodeID,
				"id_range":    node.IDRange,
				"frame_count": node.FrameCount,
			},
		}
		database.GetDB().Create(scanResult)
	}

	endTime := time.Now()
	task.Status = "completed"
	task.Progress = 100
	task.EndTime = &endTime
	database.GetDB().Save(task)

	canDuration := endTime.Sub(*task.StartTime)
	logger.GetLogger().Infof("CAN scan task %d completed in %s: %d IDs, %d anomalies",
		task.ID, canDuration, result.UniqueIDs, len(result.Anomalies))
}

// scanRS485Bus 扫描 RS-485 总线
func (h *ScanHandler) scanRS485Bus(ctx context.Context, task *models.ScanTask, req struct {
	Target      string                 `json:"target" binding:"required"`
	PortRange   string                 `json:"port_range"`
	ScanType    string                 `json:"scan_type" binding:"required,oneof=port service vuln can rs485"`
	NetworkType string                 `json:"network_type"`
	Config      map[string]interface{} `json:"config"`
}) {
	// 获取串口配置
	port := "/dev/ttyUSB0"
	if val, ok := req.Config["port"].(string); ok {
		port = val
	}

	baudRate := 9600
	if val, ok := req.Config["baud_rate"].(float64); ok {
		baudRate = int(val)
	}

	// 设置 RS485 扫描器
	h.scanner.SetRS485Scanner(port, baudRate)

	// 获取地址范围
	startAddr := byte(1)
	endAddr := byte(247)
	if val, ok := req.Config["start_addr"].(float64); ok {
		startAddr = byte(val)
	}
	if val, ok := req.Config["end_addr"].(float64); ok {
		endAddr = byte(val)
	}

	// 执行 Modbus 设备扫描
	result, err := h.scanner.RS485Scanner.ScanModbusDevices(ctx, startAddr, endAddr)
	if err != nil {
		task.Status = "failed"
		task.Error = err.Error()
		database.GetDB().Save(task)
		logger.GetLogger().Errorf("RS485 scan failed: %v", err)
		return
	}

	// 保存设备信息
	for _, device := range result.ActiveDevices {
		scanResult := &models.ScanResult{
			TaskID:      task.ID,
			ResultType:  "modbus_device",
			Target:      port,
			Description: fmt.Sprintf("Modbus Device at address %d, Response: %s", device.SlaveID, device.ResponseTime),
			Details: models.JSON{
				"slave_id":        device.SlaveID,
				"response_time":   device.ResponseTime.String(),
				"supported_funcs": device.SupportedFuncs,
				"fingerprint":     device.Fingerprint,
				"vendor_id":       device.VendorID,
				"product_code":    device.ProductCode,
				"major_minor_rev": device.MajorMinorRev,
			},
		}
		database.GetDB().Create(scanResult)
	}

	task.Progress = 80
	database.GetDB().Save(task)

	// 保存漏洞信息
	for _, vuln := range result.Vulnerabilities {
		scanResult := &models.ScanResult{
			TaskID:      task.ID,
			ResultType:  "vulnerability",
			Target:      port,
			Severity:    vuln.Severity,
			Title:       vuln.Type,
			Description: vuln.Description,
			Details: models.JSON{
				"slave_id":  vuln.SlaveID,
				"timestamp": vuln.Timestamp,
				"details":   vuln.Details,
			},
		}
		database.GetDB().Create(scanResult)
	}

	endTime := time.Now()
	task.Status = "completed"
	task.Progress = 100
	task.EndTime = &endTime
	database.GetDB().Save(task)

	rs485Duration := endTime.Sub(*task.StartTime)
	logger.GetLogger().Infof("RS485 scan task %d completed in %s: %d devices, %d vulnerabilities",
		task.ID, rs485Duration, result.TotalDevices, len(result.Vulnerabilities))
}

// ListTasks 列出扫描任务（支持分页）
func (h *ScanHandler) ListTasks(c *gin.Context) {
	// 获取分页参数
	params := GetPaginationParams(c)

	// 查询总数
	var total int64
	database.GetDB().Model(&models.ScanTask{}).Count(&total)

	// 查询任务列表
	var tasks []models.ScanTask
	database.GetDB().
		Order("created_at DESC").
		Offset(params.GetOffset()).
		Limit(params.GetLimit()).
		Find(&tasks)

	// 计算元数据
	meta := CalculateMeta(total, params.Page, params.PageSize)

	// 返回标准响应
	RespondSuccessWithMeta(c, gin.H{"tasks": tasks}, meta)
}

// GetTask 获取任务详情
func (h *ScanHandler) GetTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.ScanTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	RespondSuccess(c, gin.H{"task": task})
}

// HandleWebSocket WebSocket 处理
func (h *ScanHandler) HandleWebSocket(c *gin.Context) {
	// 实现 WebSocket 连接
}

// GetTaskResults 获取扫描任务结果
func (h *ScanHandler) GetTaskResults(c *gin.Context) {
	taskID := c.Param("id")

	// 获取任务信息
	var task models.ScanTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	// 获取扫描结果
	var results []models.ScanResult
	database.GetDB().Where("task_id = ?", taskID).Find(&results)

	RespondSuccess(c, gin.H{
		"task":    task,
		"results": results,
	})
}

// GetTaskVulnerabilities 获取任务漏洞列表
func (h *ScanHandler) GetTaskVulnerabilities(c *gin.Context) {
	taskID := c.Param("id")

	// 获取漏洞类型的结果
	var results []models.ScanResult
	database.GetDB().Where("task_id = ? AND result_type = ?", taskID, "vulnerability").Find(&results)

	RespondSuccess(c, gin.H{
		"vulnerabilities": results,
	})
}

// StopTask 停止扫描任务
func (h *ScanHandler) StopTask(c *gin.Context) {
	taskID := c.Param("id")

	// 获取任务
	var task models.ScanTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	// 更新任务状态
	task.Status = "stopped"
	database.GetDB().Save(&task)

	RespondSuccess(c, gin.H{"message": "Task stopped"})
}

// DeleteTask 删除扫描任务
func (h *ScanHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("id")

	// 删除结果
	database.GetDB().Where("task_id = ?", taskID).Delete(&models.ScanResult{})

	// 删除任务
	database.GetDB().Delete(&models.ScanTask{}, taskID)

	RespondSuccess(c, gin.H{"message": "Task deleted"})
}

// ExportTaskResults 导出扫描结果
func (h *ScanHandler) ExportTaskResults(c *gin.Context) {
	taskID := c.Param("id")
	format := c.Query("format") // csv, json

	if format == "" {
		format = "json"
	}

	// 获取任务信息
	var task models.ScanTask
	if err := database.GetDB().First(&task, taskID).Error; err != nil {
		RespondNotFound(c, "Task not found")
		return
	}

	// 获取扫描结果
	var results []models.ScanResult
	database.GetDB().Where("task_id = ?", taskID).Find(&results)

	if len(results) == 0 {
		RespondNotFound(c, "No results found")
		return
	}

	// 转换为指针切片
	resultPtrs := make([]*models.ScanResult, len(results))
	for i := range results {
		resultPtrs[i] = &results[i]
	}

	var filepath string
	var err error

	// 根据格式导出
	switch format {
	case "csv":
		filepath, err = h.exporter.ExportScanResultToCSV(&task, resultPtrs)
	case "json":
		filepath, err = h.exporter.ExportScanResultToJSON(&task, resultPtrs)
	default:
		RespondBadRequest(c, "Invalid format. Supported: csv, json")
		return
	}

	if err != nil {
		logger.GetLogger().Errorf("Failed to export scan results: %v", err)
		RespondInternalError(c, "Export failed")
		return
	}

	// 返回文件
	c.FileAttachment(filepath, filepath[len("./data/exports/"):])
}
