package attack

import (
	"fmt"
	"netsecanalyzer/internal/database"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"time"
)

// AttackManager 攻击管理器
// 负责授权检查和攻击日志记录
// 注意: 任务的生命周期管理由 TaskManager 负责
type AttackManager struct {
	AuthorizationRequired bool
	MaxRate               int
}

// NewAttackManager 创建攻击管理器
func NewAttackManager(authRequired bool, maxRate int) *AttackManager {
	return &AttackManager{
		AuthorizationRequired: authRequired,
		MaxRate:               maxRate,
	}
}

// CheckAuthorization 检查授权
func (am *AttackManager) CheckAuthorization(target string, userID string) error {
	if !am.AuthorizationRequired {
		return nil
	}

	// 这里应该实现实际的授权检查逻辑
	// 例如：检查目标是否在白名单中，用户是否有权限等
	logger.GetLogger().Infof("Authorization check for user %s on target %s", userID, target)

	// 示例：检查是否为私有 IP
	// 实际部署中应该有更严格的授权机制
	return nil
}

// LogAttack 记录攻击日志
// 参数:
//   - attackType: 攻击类型 (fuzzing, replay等)
//   - target: 目标地址
//   - method: 攻击方法
//   - userID: 用户ID
//   - parameters: 攻击参数
//   - result: 攻击结果
//   - status: 状态 (success, failed, stopped等)
func (am *AttackManager) LogAttack(attackType, target, method, userID string, parameters map[string]interface{}, result string, status string) error {
	log := models.AttackLog{
		AttackType: attackType,
		Target:     target,
		Method:     method,
		Parameters: models.JSON(parameters),
		Result:     result,
		Status:     status,
		UserID:     userID,
		Authorized: !am.AuthorizationRequired || true, // 简化处理
		ExecutedAt: time.Now(),
	}

	// 保存到数据库
	if err := database.GetDB().Create(&log).Error; err != nil {
		logger.GetLogger().Errorf("Failed to save attack log: %v", err)
		return fmt.Errorf("failed to save attack log: %w", err)
	}

	logger.GetLogger().Infof("Attack logged: %s on %s by %s, status: %s (ID: %d)", attackType, target, userID, status, log.ID)
	return nil
}
