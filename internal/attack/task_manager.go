package attack

import (
	"context"
	"fmt"
	"netsecanalyzer/pkg/logger"
	"sync"
)

// TaskManager 管理所有正在运行的攻击任务（Fuzzing、Replay等）
// 统一使用 context 取消机制，确保任务可以被优雅地停止
// 线程安全：所有公共方法都使用互斥锁保护
type TaskManager struct {
	tasks map[uint]context.CancelFunc // taskID -> cancel function
	mu    sync.RWMutex                // 读写锁，支持并发读取
}

// NewTaskManager 创建任务管理器实例
// 返回一个初始化好的 TaskManager
func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks: make(map[uint]context.CancelFunc),
	}
}

// AddTask 注册一个新的任务到管理器
// 参数:
//   - taskID: 任务的唯一标识符
//   - cancel: 用于取消任务的 context.CancelFunc
//
// 注意: 如果 taskID 已存在，会覆盖旧的 cancel 函数
func (tm *TaskManager) AddTask(taskID uint, cancel context.CancelFunc) {
	if cancel == nil {
		logger.GetLogger().Warnf("Attempted to add task %d with nil cancel function", taskID)
		return
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// 检查是否已存在
	if _, exists := tm.tasks[taskID]; exists {
		logger.GetLogger().Warnf("Task %d already exists, will be replaced", taskID)
	}

	tm.tasks[taskID] = cancel
	logger.GetLogger().Debugf("Task %d added to manager (total: %d)", taskID, len(tm.tasks))
}

// RemoveTask 从管理器中移除任务
// 参数:
//   - taskID: 要移除的任务ID
//
// 注意: 此方法只移除记录，不会调用 cancel 函数
// 通常在任务自然结束后调用
func (tm *TaskManager) RemoveTask(taskID uint) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.tasks[taskID]; exists {
		delete(tm.tasks, taskID)
		logger.GetLogger().Debugf("Task %d removed from manager (remaining: %d)", taskID, len(tm.tasks))
	}
}

// StopTask 停止指定的任务
// 参数:
//   - taskID: 要停止的任务ID
//
// 返回:
//   - bool: true 表示成功发送停止信号，false 表示任务不存在
//
// 注意: 此方法会调用 cancel 函数并从管理器中移除任务
func (tm *TaskManager) StopTask(taskID uint) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	cancel, exists := tm.tasks[taskID]
	if !exists {
		logger.GetLogger().Warnf("Attempted to stop non-existent task %d", taskID)
		return false
	}

	// 调用取消函数
	cancel()

	// 从管理器中移除
	delete(tm.tasks, taskID)

	logger.GetLogger().Infof("Task %d stopped and removed from manager (remaining: %d)", taskID, len(tm.tasks))
	return true
}

// IsRunning 检查指定任务是否正在运行
// 参数:
//   - taskID: 要检查的任务ID
//
// 返回:
//   - bool: true 表示任务正在运行，false 表示任务不存在或已停止
func (tm *TaskManager) IsRunning(taskID uint) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	_, exists := tm.tasks[taskID]
	return exists
}

// GetRunningCount 获取当前正在运行的任务数量
// 返回:
//   - int: 正在运行的任务数量
func (tm *TaskManager) GetRunningCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	return len(tm.tasks)
}

// GetRunningTaskIDs 获取所有正在运行的任务ID列表
// 返回:
//   - []uint: 任务ID切片
func (tm *TaskManager) GetRunningTaskIDs() []uint {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	ids := make([]uint, 0, len(tm.tasks))
	for id := range tm.tasks {
		ids = append(ids, id)
	}

	return ids
}

// StopAll 停止所有正在运行的任务
// 返回:
//   - int: 成功停止的任务数量
//
// 注意: 此方法会调用所有任务的 cancel 函数并清空管理器
func (tm *TaskManager) StopAll() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	count := len(tm.tasks)
	if count == 0 {
		return 0
	}

	logger.GetLogger().Infof("Stopping all %d running tasks", count)

	// 调用所有 cancel 函数
	for taskID, cancel := range tm.tasks {
		cancel()
		logger.GetLogger().Debugf("Task %d stopped", taskID)
	}

	// 清空管理器
	tm.tasks = make(map[uint]context.CancelFunc)

	logger.GetLogger().Infof("All %d tasks stopped", count)
	return count
}

// String 返回 TaskManager 的字符串表示
// 实现 fmt.Stringer 接口
func (tm *TaskManager) String() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	return fmt.Sprintf("TaskManager{running: %d tasks}", len(tm.tasks))
}
