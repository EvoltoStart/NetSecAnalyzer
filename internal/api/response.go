package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// APIResponse 标准 API 响应结构
type APIResponse struct {
	Success bool        `json:"success"`         // 请求是否成功
	Data    interface{} `json:"data,omitempty"`  // 响应数据
	Error   string      `json:"error,omitempty"` // 错误消息
	Meta    *Meta       `json:"meta,omitempty"`  // 元数据（分页等）
}

// Meta 元数据结构（用于分页）
type Meta struct {
	Total      int64 `json:"total"`      // 总记录数
	Page       int   `json:"page"`       // 当前页码
	PageSize   int   `json:"pageSize"`   // 每页大小
	TotalPages int   `json:"totalPages"` // 总页数
}

// RespondSuccess 返回成功响应
func RespondSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// RespondSuccessWithMeta 返回带元数据的成功响应（用于分页）
func RespondSuccessWithMeta(c *gin.Context, data interface{}, meta *Meta) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

// RespondError 返回错误响应
func RespondError(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, APIResponse{
		Success: false,
		Error:   message,
	})
}

// RespondBadRequest 返回 400 错误
func RespondBadRequest(c *gin.Context, message string) {
	RespondError(c, http.StatusBadRequest, message)
}

// RespondNotFound 返回 404 错误
func RespondNotFound(c *gin.Context, message string) {
	RespondError(c, http.StatusNotFound, message)
}

// RespondInternalError 返回 500 错误
func RespondInternalError(c *gin.Context, message string) {
	RespondError(c, http.StatusInternalServerError, message)
}

// CalculateMeta 计算分页元数据
func CalculateMeta(total int64, page, pageSize int) *Meta {
	totalPages := int(total) / pageSize
	if int(total)%pageSize != 0 {
		totalPages++
	}

	return &Meta{
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}
}

// PaginationParams 分页参数结构
type PaginationParams struct {
	Page     int `form:"page" binding:"omitempty,min=1"`                  // 页码（默认 1）
	PageSize int `form:"page_size" binding:"omitempty,min=1,max=1000000"` // 每页大小（默认 20，最大 1000000）
}

// GetPaginationParams 从请求中获取分页参数
func GetPaginationParams(c *gin.Context) PaginationParams {
	var params PaginationParams

	// 绑定查询参数
	if err := c.ShouldBindQuery(&params); err != nil {
		// 使用默认值
		params.Page = 1
		params.PageSize = 20
		return params
	}

	// 设置默认值
	if params.Page == 0 {
		params.Page = 1
	}
	if params.PageSize == 0 {
		params.PageSize = 20
	}

	return params
}

// GetOffset 计算数据库查询的偏移量
func (p PaginationParams) GetOffset() int {
	return (p.Page - 1) * p.PageSize
}

// GetLimit 获取查询限制数量
func (p PaginationParams) GetLimit() int {
	return p.PageSize
}
