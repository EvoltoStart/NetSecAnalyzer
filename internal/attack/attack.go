package attack

import (
	"fmt"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"sync"
	"time"
)

// AttackManager 攻击管理器
type AttackManager struct {
	AuthorizationRequired bool
	MaxRate               int
	mu                    sync.Mutex
	activeAttacks         map[string]*AttackSession
}

// AttackSession 攻击会话
type AttackSession struct {
	ID         string
	Type       string
	Target     string
	StartTime  time.Time
	Status     string
	StopChan   chan struct{}
	ResultChan chan *AttackResult
}

// AttackResult 攻击结果
type AttackResult struct {
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// NewAttackManager 创建攻击管理器
func NewAttackManager(authRequired bool, maxRate int) *AttackManager {
	return &AttackManager{
		AuthorizationRequired: authRequired,
		MaxRate:               maxRate,
		activeAttacks:         make(map[string]*AttackSession),
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

	// 这里应该保存到数据库
	logger.GetLogger().Infof("Attack logged: %s on %s by %s, status: %s", attackType, target, userID, status)
	_ = log

	return nil
}

// CreateSession 创建攻击会话
func (am *AttackManager) CreateSession(sessionID, attackType, target string) *AttackSession {
	am.mu.Lock()
	defer am.mu.Unlock()

	session := &AttackSession{
		ID:         sessionID,
		Type:       attackType,
		Target:     target,
		StartTime:  time.Now(),
		Status:     "running",
		StopChan:   make(chan struct{}),
		ResultChan: make(chan *AttackResult, 100),
	}

	am.activeAttacks[sessionID] = session
	return session
}

// StopSession 停止攻击会话
func (am *AttackManager) StopSession(sessionID string) error {
	am.mu.Lock()
	session, exists := am.activeAttacks[sessionID]
	am.mu.Unlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	close(session.StopChan)
	session.Status = "stopped"

	am.mu.Lock()
	delete(am.activeAttacks, sessionID)
	am.mu.Unlock()

	logger.GetLogger().Infof("Attack session stopped: %s", sessionID)
	return nil
}

// GetActiveAttacks 获取活动攻击
func (am *AttackManager) GetActiveAttacks() []*AttackSession {
	am.mu.Lock()
	defer am.mu.Unlock()

	sessions := make([]*AttackSession, 0, len(am.activeAttacks))
	for _, session := range am.activeAttacks {
		sessions = append(sessions, session)
	}
	return sessions
}
