package api

import (
	"netsecanalyzer/internal/database"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// IDSRulesHandler IDS规则管理处理器
type IDSRulesHandler struct{}

// NewIDSRulesHandler 创建IDS规则处理器
func NewIDSRulesHandler() *IDSRulesHandler {
	return &IDSRulesHandler{}
}

// IDSRule IDS规则模型
type IDSRule struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:255;not null" json:"name"`
	Type        string    `gorm:"size:50;not null;index" json:"type"` // port_scan, dos, brute_force, etc.
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	Severity    string    `gorm:"size:20;not null" json:"severity"` // low, medium, high, critical
	Pattern     string    `gorm:"type:text" json:"pattern"`         // 匹配模式
	Threshold   int       `json:"threshold"`                        // 触发阈值
	TimeWindow  int       `json:"timeWindow"`                       // 时间窗口（秒）
	Action      string    `gorm:"size:50" json:"action"`            // alert, block, log
	Description string    `gorm:"type:text" json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// CreateIDSRuleRequest 创建规则请求
type CreateIDSRuleRequest struct {
	Name        string `json:"name" binding:"required"`
	Type        string `json:"type" binding:"required,oneof=port_scan dos brute_force sql_injection xss malware"`
	Enabled     bool   `json:"enabled"`
	Severity    string `json:"severity" binding:"required,oneof=low medium high critical"`
	Pattern     string `json:"pattern"`
	Threshold   int    `json:"threshold" binding:"min=1"`
	TimeWindow  int    `json:"timeWindow" binding:"min=1"`
	Action      string `json:"action" binding:"required,oneof=alert block log"`
	Description string `json:"description"`
}

// UpdateIDSRuleRequest 更新规则请求
type UpdateIDSRuleRequest struct {
	Name        string `json:"name"`
	Enabled     *bool  `json:"enabled"`
	Severity    string `json:"severity" binding:"omitempty,oneof=low medium high critical"`
	Pattern     string `json:"pattern"`
	Threshold   *int   `json:"threshold" binding:"omitempty,min=1"`
	TimeWindow  *int   `json:"timeWindow" binding:"omitempty,min=1"`
	Action      string `json:"action" binding:"omitempty,oneof=alert block log"`
	Description string `json:"description"`
}

// CreateIDSRule 创建IDS规则
func (h *IDSRulesHandler) CreateIDSRule(c *gin.Context) {
	var req CreateIDSRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	// 检查规则名称是否已存在
	var existingRule IDSRule
	if err := database.GetDB().Where("name = ?", req.Name).First(&existingRule).Error; err == nil {
		RespondBadRequest(c, "Rule name already exists")
		return
	}

	// 创建规则
	rule := &IDSRule{
		Name:        req.Name,
		Type:        req.Type,
		Enabled:     req.Enabled,
		Severity:    req.Severity,
		Pattern:     req.Pattern,
		Threshold:   req.Threshold,
		TimeWindow:  req.TimeWindow,
		Action:      req.Action,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := database.GetDB().Create(rule).Error; err != nil {
		RespondInternalError(c, "Failed to create rule")
		return
	}

	RespondSuccess(c, gin.H{"rule": rule})
}

// GetIDSRules 获取IDS规则列表
func (h *IDSRulesHandler) GetIDSRules(c *gin.Context) {
	// 获取分页参数
	params := GetPaginationParams(c)

	// 获取过滤参数
	ruleType := c.Query("type")
	enabled := c.Query("enabled")
	severity := c.Query("severity")

	// 构建查询
	query := database.GetDB().Model(&IDSRule{})

	if ruleType != "" {
		query = query.Where("type = ?", ruleType)
	}
	if enabled != "" {
		if enabledBool, err := strconv.ParseBool(enabled); err == nil {
			query = query.Where("enabled = ?", enabledBool)
		}
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}

	// 查询总数
	var total int64
	query.Count(&total)

	// 查询规则列表
	var rules []IDSRule
	query.Order("created_at DESC").
		Offset(params.GetOffset()).
		Limit(params.GetLimit()).
		Find(&rules)

	// 计算元数据
	meta := CalculateMeta(total, params.Page, params.PageSize)

	// 返回标准响应
	RespondSuccessWithMeta(c, gin.H{"rules": rules}, meta)
}

// GetIDSRule 获取单个IDS规则
func (h *IDSRulesHandler) GetIDSRule(c *gin.Context) {
	ruleID := c.Param("id")

	var rule IDSRule
	if err := database.GetDB().First(&rule, ruleID).Error; err != nil {
		RespondNotFound(c, "Rule not found")
		return
	}

	RespondSuccess(c, gin.H{"rule": rule})
}

// UpdateIDSRule 更新IDS规则
func (h *IDSRulesHandler) UpdateIDSRule(c *gin.Context) {
	ruleID := c.Param("id")

	var req UpdateIDSRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	var rule IDSRule
	if err := database.GetDB().First(&rule, ruleID).Error; err != nil {
		RespondNotFound(c, "Rule not found")
		return
	}

	// 更新字段
	if req.Name != "" {
		// 检查名称是否已被其他规则使用
		var existingRule IDSRule
		if err := database.GetDB().Where("name = ? AND id != ?", req.Name, rule.ID).First(&existingRule).Error; err == nil {
			RespondBadRequest(c, "Rule name already exists")
			return
		}
		rule.Name = req.Name
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Severity != "" {
		rule.Severity = req.Severity
	}
	if req.Pattern != "" {
		rule.Pattern = req.Pattern
	}
	if req.Threshold != nil {
		rule.Threshold = *req.Threshold
	}
	if req.TimeWindow != nil {
		rule.TimeWindow = *req.TimeWindow
	}
	if req.Action != "" {
		rule.Action = req.Action
	}
	if req.Description != "" {
		rule.Description = req.Description
	}

	rule.UpdatedAt = time.Now()

	if err := database.GetDB().Save(&rule).Error; err != nil {
		RespondInternalError(c, "Failed to update rule")
		return
	}

	RespondSuccess(c, gin.H{"rule": rule})
}

// DeleteIDSRule 删除IDS规则
func (h *IDSRulesHandler) DeleteIDSRule(c *gin.Context) {
	ruleID := c.Param("id")

	var rule IDSRule
	if err := database.GetDB().First(&rule, ruleID).Error; err != nil {
		RespondNotFound(c, "Rule not found")
		return
	}

	if err := database.GetDB().Delete(&rule).Error; err != nil {
		RespondInternalError(c, "Failed to delete rule")
		return
	}

	RespondSuccess(c, gin.H{"message": "Rule deleted successfully"})
}

// ToggleIDSRule 切换规则启用状态
func (h *IDSRulesHandler) ToggleIDSRule(c *gin.Context) {
	ruleID := c.Param("id")

	var rule IDSRule
	if err := database.GetDB().First(&rule, ruleID).Error; err != nil {
		RespondNotFound(c, "Rule not found")
		return
	}

	rule.Enabled = !rule.Enabled
	rule.UpdatedAt = time.Now()

	if err := database.GetDB().Save(&rule).Error; err != nil {
		RespondInternalError(c, "Failed to toggle rule")
		return
	}

	RespondSuccess(c, gin.H{
		"rule":    rule,
		"message": "Rule toggled successfully",
	})
}

// GetIDSRuleTypes 获取支持的规则类型
func (h *IDSRulesHandler) GetIDSRuleTypes(c *gin.Context) {
	types := []map[string]interface{}{
		{
			"value":       "port_scan",
			"label":       "端口扫描",
			"description": "检测端口扫描行为",
		},
		{
			"value":       "dos",
			"label":       "DoS 攻击",
			"description": "检测拒绝服务攻击",
		},
		{
			"value":       "brute_force",
			"label":       "暴力破解",
			"description": "检测暴力破解攻击",
		},
		{
			"value":       "sql_injection",
			"label":       "SQL 注入",
			"description": "检测 SQL 注入攻击",
		},
		{
			"value":       "xss",
			"label":       "XSS 攻击",
			"description": "检测跨站脚本攻击",
		},
		{
			"value":       "malware",
			"label":       "恶意软件",
			"description": "检测恶意软件通信",
		},
	}

	RespondSuccess(c, gin.H{"types": types})
}

// GetIDSRuleStats 获取规则统计信息
func (h *IDSRulesHandler) GetIDSRuleStats(c *gin.Context) {
	var stats struct {
		Total    int64 `json:"total"`
		Enabled  int64 `json:"enabled"`
		Disabled int64 `json:"disabled"`
	}

	db := database.GetDB()

	// 总规则数
	db.Model(&IDSRule{}).Count(&stats.Total)

	// 启用的规则数
	db.Model(&IDSRule{}).Where("enabled = ?", true).Count(&stats.Enabled)

	// 禁用的规则数
	db.Model(&IDSRule{}).Where("enabled = ?", false).Count(&stats.Disabled)

	// 按类型统计
	var typeStats []struct {
		Type  string `json:"type"`
		Count int64  `json:"count"`
	}
	db.Model(&IDSRule{}).
		Select("type, COUNT(*) as count").
		Group("type").
		Scan(&typeStats)

	// 按严重程度统计
	var severityStats []struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	db.Model(&IDSRule{}).
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityStats)

	RespondSuccess(c, gin.H{
		"overview":   stats,
		"byType":     typeStats,
		"bySeverity": severityStats,
	})
}

// BatchUpdateIDSRules 批量更新规则
func (h *IDSRulesHandler) BatchUpdateIDSRules(c *gin.Context) {
	var req struct {
		RuleIDs []uint `json:"ruleIds" binding:"required"`
		Updates struct {
			Enabled  *bool  `json:"enabled"`
			Severity string `json:"severity" binding:"omitempty,oneof=low medium high critical"`
			Action   string `json:"action" binding:"omitempty,oneof=alert block log"`
		} `json:"updates" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	if len(req.RuleIDs) == 0 {
		RespondBadRequest(c, "No rule IDs provided")
		return
	}

	// 构建更新数据
	updates := make(map[string]interface{})
	if req.Updates.Enabled != nil {
		updates["enabled"] = *req.Updates.Enabled
	}
	if req.Updates.Severity != "" {
		updates["severity"] = req.Updates.Severity
	}
	if req.Updates.Action != "" {
		updates["action"] = req.Updates.Action
	}
	updates["updated_at"] = time.Now()

	if len(updates) == 1 { // 只有 updated_at
		RespondBadRequest(c, "No valid updates provided")
		return
	}

	// 批量更新
	result := database.GetDB().Model(&IDSRule{}).
		Where("id IN ?", req.RuleIDs).
		Updates(updates)

	if result.Error != nil {
		RespondInternalError(c, "Failed to batch update rules")
		return
	}

	RespondSuccess(c, gin.H{
		"message":      "Rules updated successfully",
		"updatedCount": result.RowsAffected,
	})
}

// ExportIDSRules 导出规则
func (h *IDSRulesHandler) ExportIDSRules(c *gin.Context) {
	var rules []IDSRule
	if err := database.GetDB().Find(&rules).Error; err != nil {
		RespondInternalError(c, "Failed to export rules")
		return
	}

	// 设置响应头
	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", "attachment; filename=ids_rules.json")

	c.JSON(200, gin.H{
		"version":     "1.0",
		"exported_at": time.Now(),
		"rules":       rules,
	})
}

// ImportIDSRules 导入规则
func (h *IDSRulesHandler) ImportIDSRules(c *gin.Context) {
	var req struct {
		Rules []CreateIDSRuleRequest `json:"rules" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		RespondBadRequest(c, err.Error())
		return
	}

	if len(req.Rules) == 0 {
		RespondBadRequest(c, "No rules to import")
		return
	}

	var imported int
	var skipped int
	var errors []string

	for _, ruleReq := range req.Rules {
		// 检查规则名称是否已存在
		var existingRule IDSRule
		if err := database.GetDB().Where("name = ?", ruleReq.Name).First(&existingRule).Error; err == nil {
			skipped++
			errors = append(errors, "Rule '"+ruleReq.Name+"' already exists")
			continue
		}

		// 创建规则
		rule := &IDSRule{
			Name:        ruleReq.Name,
			Type:        ruleReq.Type,
			Enabled:     ruleReq.Enabled,
			Severity:    ruleReq.Severity,
			Pattern:     ruleReq.Pattern,
			Threshold:   ruleReq.Threshold,
			TimeWindow:  ruleReq.TimeWindow,
			Action:      ruleReq.Action,
			Description: ruleReq.Description,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if err := database.GetDB().Create(rule).Error; err != nil {
			skipped++
			errors = append(errors, "Failed to create rule '"+ruleReq.Name+"': "+err.Error())
			continue
		}

		imported++
	}

	RespondSuccess(c, gin.H{
		"message":  "Import completed",
		"imported": imported,
		"skipped":  skipped,
		"errors":   errors,
	})
}
