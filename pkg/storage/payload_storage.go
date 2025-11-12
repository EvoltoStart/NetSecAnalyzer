package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PayloadStorage Payload 存储管理器
type PayloadStorage struct {
	basePath      string
	maxFileSize   int64 // 单个文件最大大小（字节）
	retentionDays int   // 数据保留天数
	mu            sync.RWMutex
}

// NewPayloadStorage 创建 Payload 存储管理器
func NewPayloadStorage(basePath string, maxFileSize int64, retentionDays int) (*PayloadStorage, error) {
	// 创建基础目录
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base path: %w", err)
	}

	ps := &PayloadStorage{
		basePath:      basePath,
		maxFileSize:   maxFileSize,
		retentionDays: retentionDays,
	}

	return ps, nil
}

// Save 保存 Payload 到文件
// 返回文件路径（相对于 basePath）
func (ps *PayloadStorage) Save(sessionID uint, packetID uint, payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", nil
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// 按日期和会话ID组织目录结构
	// 例如: payloads/2024/01/15/session_123/packet_456.bin
	now := time.Now()
	dateDir := filepath.Join(
		ps.basePath,
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", now.Month()),
		fmt.Sprintf("%02d", now.Day()),
		fmt.Sprintf("session_%d", sessionID),
	)

	// 创建目录
	if err := os.MkdirAll(dateDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// 生成文件名（使用 packet ID）
	filename := fmt.Sprintf("packet_%d.bin", packetID)
	fullPath := filepath.Join(dateDir, filename)

	// 写入文件
	if err := ioutil.WriteFile(fullPath, payload, 0644); err != nil {
		return "", fmt.Errorf("failed to write payload file: %w", err)
	}

	// 返回相对路径
	relPath, err := filepath.Rel(ps.basePath, fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to get relative path: %w", err)
	}

	return relPath, nil
}

// SaveWithHash 保存 Payload 并使用哈希去重
// 返回文件路径和哈希值
func (ps *PayloadStorage) SaveWithHash(sessionID uint, payload []byte) (string, string, error) {
	if len(payload) == 0 {
		return "", "", nil
	}

	// 计算哈希
	hash := sha256.Sum256(payload)
	hashStr := hex.EncodeToString(hash[:])

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// 按哈希前缀组织目录（避免单个目录文件过多）
	// 例如: payloads/hash/ab/cd/abcdef123456...
	hashDir := filepath.Join(
		ps.basePath,
		"hash",
		hashStr[:2],
		hashStr[2:4],
	)

	// 创建目录
	if err := os.MkdirAll(hashDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create directory: %w", err)
	}

	filename := hashStr + ".bin"
	fullPath := filepath.Join(hashDir, filename)

	// 如果文件已存在（去重），直接返回路径
	if _, err := os.Stat(fullPath); err == nil {
		relPath, _ := filepath.Rel(ps.basePath, fullPath)
		return relPath, hashStr, nil
	}

	// 写入文件
	if err := ioutil.WriteFile(fullPath, payload, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write payload file: %w", err)
	}

	// 返回相对路径
	relPath, err := filepath.Rel(ps.basePath, fullPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to get relative path: %w", err)
	}

	return relPath, hashStr, nil
}

// Load 从文件加载 Payload
func (ps *PayloadStorage) Load(relPath string) ([]byte, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	fullPath := filepath.Join(ps.basePath, relPath)

	// 检查文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("payload file not found: %s", relPath)
	}

	// 读取文件
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file: %w", err)
	}

	return data, nil
}

// Delete 删除 Payload 文件
func (ps *PayloadStorage) Delete(relPath string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	fullPath := filepath.Join(ps.basePath, relPath)
	return os.Remove(fullPath)
}

// CleanupOldFiles 清理过期文件
func (ps *PayloadStorage) CleanupOldFiles() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	cutoffTime := time.Now().AddDate(0, 0, -ps.retentionDays)

	return filepath.Walk(ps.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 检查文件修改时间
		if info.ModTime().Before(cutoffTime) {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove old file %s: %w", path, err)
			}
		}

		return nil
	})
}

// GetStorageStats 获取存储统计信息
func (ps *PayloadStorage) GetStorageStats() (totalFiles int64, totalSize int64, err error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	err = filepath.Walk(ps.basePath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !info.IsDir() {
			totalFiles++
			totalSize += info.Size()
		}

		return nil
	})

	return totalFiles, totalSize, err
}

// GetSessionPath 获取会话的存储路径
func (ps *PayloadStorage) GetSessionPath(sessionID uint) string {
	now := time.Now()
	return filepath.Join(
		ps.basePath,
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", now.Month()),
		fmt.Sprintf("%02d", now.Day()),
		fmt.Sprintf("session_%d", sessionID),
	)
}

// DeleteSession 删除整个会话的 Payload 文件
func (ps *PayloadStorage) DeleteSession(sessionID uint, date time.Time) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	sessionPath := filepath.Join(
		ps.basePath,
		fmt.Sprintf("%04d", date.Year()),
		fmt.Sprintf("%02d", date.Month()),
		fmt.Sprintf("%02d", date.Day()),
		fmt.Sprintf("session_%d", sessionID),
	)

	return os.RemoveAll(sessionPath)
}
