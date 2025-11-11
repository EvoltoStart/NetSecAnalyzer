package api

import (
	"context"
	"netsecanalyzer/internal/attack"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"

	"github.com/gin-gonic/gin"
)

// AttackHandler 攻击处理器
type AttackHandler struct {
	manager  *attack.AttackManager
	replayer *attack.Replayer
	fuzzer   *attack.Fuzzer
}

// NewAttackHandler 创建攻击处理器
func NewAttackHandler(m *attack.AttackManager) *AttackHandler {
	return &AttackHandler{
		manager:  m,
		replayer: attack.NewReplayer(m),
		fuzzer:   attack.NewFuzzer(m),
	}
}

// ReplayPackets 重放数据包
func (h *AttackHandler) ReplayPackets(c *gin.Context) {
	var req struct {
		SessionID       uint    `json:"session_id" binding:"required"`
		Interface       string  `json:"interface" binding:"required"`
		SpeedMultiplier float64 `json:"speed_multiplier"`
		UserID          string  `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 检查授权
	if err := h.manager.CheckAuthorization("replay", req.UserID); err != nil {
		c.JSON(403, gin.H{"error": "Unauthorized"})
		return
	}

	// 获取数据包
	var packets []models.Packet
	database.GetDB().Where("session_id = ?", req.SessionID).Find(&packets)

	if len(packets) == 0 {
		c.JSON(404, gin.H{"error": "No packets found"})
		return
	}

	// 转换为指针切片
	packetPtrs := make([]*models.Packet, len(packets))
	for i := range packets {
		packetPtrs[i] = &packets[i]
	}

	// 异步执行重放
	go func() {
		ctx := context.Background()
		if err := h.replayer.ReplayPackets(ctx, packetPtrs, req.Interface, req.SpeedMultiplier); err != nil {
			h.manager.LogAttack("replay", req.Interface, "packet_replay", req.UserID, nil, err.Error(), "failed")
			return
		}
		h.manager.LogAttack("replay", req.Interface, "packet_replay", req.UserID, nil, "success", "success")
	}()

	c.JSON(200, gin.H{"message": "Replay started"})
}

// StartFuzzing 启动 Fuzzing
func (h *AttackHandler) StartFuzzing(c *gin.Context) {
	var req struct {
		Target       string  `json:"target" binding:"required"`
		Port         int     `json:"port" binding:"required"`
		Protocol     string  `json:"protocol" binding:"required"`
		Template     string  `json:"template"`
		Iterations   int     `json:"iterations"`
		MutationRate float64 `json:"mutation_rate"`
		UserID       string  `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 检查授权
	if err := h.manager.CheckAuthorization(req.Target, req.UserID); err != nil {
		c.JSON(403, gin.H{"error": "Unauthorized"})
		return
	}

	c.JSON(200, gin.H{"message": "Fuzzing started"})
}
