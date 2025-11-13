package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

// CaptureSession 数据采集会话
type CaptureSession struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:255;not null" json:"name"`
	Type        string     `gorm:"size:50;not null;index" json:"type"`   // ip, can, rs485
	Status      string     `gorm:"size:50;not null;index" json:"status"` // running, stopped, completed
	PacketCount int64      `json:"packet_count"`
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	Config      JSON       `gorm:"type:json" json:"config"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Packet 数据包
type Packet struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	SessionID      uint      `gorm:"index;not null" json:"session_id"`
	Timestamp      time.Time `gorm:"index" json:"timestamp"`
	Protocol       string    `gorm:"size:50;index" json:"protocol"`
	SrcAddr        string    `gorm:"size:100;index" json:"src_addr"`
	DstAddr        string    `gorm:"size:100;index" json:"dst_addr"`
	SrcPort        int       `json:"src_port,omitempty"`
	DstPort        int       `json:"dst_port,omitempty"`
	Length         int       `json:"length"`
	Payload        []byte    `gorm:"type:blob" json:"payload,omitempty"`
	PayloadPath    string    `gorm:"size:500" json:"payload_path,omitempty"`      // Payload 文件路径
	PayloadHash    string    `gorm:"size:64;index" json:"payload_hash,omitempty"` // Payload SHA256 哈希
	AnalysisResult JSON      `gorm:"type:json" json:"analysis_result,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Target       string    `gorm:"size:255;not null;index" json:"target"`
	VulnType     string    `gorm:"size:100;not null" json:"vuln_type"`
	Severity     string    `gorm:"size:50;not null;index" json:"severity"` // critical, high, medium, low, info
	CVEID        string    `gorm:"size:50;index" json:"cve_id,omitempty"`
	Title        string    `gorm:"size:500" json:"title"`
	Description  string    `gorm:"type:text" json:"description"`
	Solution     string    `gorm:"type:text" json:"solution,omitempty"`
	References   JSON      `gorm:"type:json" json:"references,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// ScanTask 扫描任务
type ScanTask struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:255;not null" json:"name"`
	Target      string     `gorm:"size:500;not null" json:"target"`
	ScanType    string     `gorm:"size:50;not null" json:"scan_type"`      // port, vuln, service, can, rs485
	NetworkType string     `gorm:"size:50;default:ip" json:"network_type"` // ip, can, rs485
	Status      string     `gorm:"size:50;not null;index" json:"status"`   // pending, running, completed, failed
	Progress    int        `json:"progress"`                               // 0-100
	Result      JSON       `gorm:"type:json" json:"result,omitempty"`
	Error       string     `gorm:"type:text" json:"error,omitempty"`
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// AttackLog 攻击操作日志
type AttackLog struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	AttackType string    `gorm:"size:100;not null;index" json:"attack_type"`
	Target     string    `gorm:"size:500;not null" json:"target"`
	Method     string    `gorm:"size:100" json:"method"`
	Parameters JSON      `gorm:"type:json" json:"parameters,omitempty"`
	Result     string    `gorm:"type:text" json:"result,omitempty"`
	Status     string    `gorm:"size:50;not null" json:"status"` // success, failed
	UserID     string    `gorm:"size:100;index" json:"user_id"`
	Authorized bool      `gorm:"not null" json:"authorized"`
	ExecutedAt time.Time `gorm:"index" json:"executed_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// AttackTask 攻击任务
type AttackTask struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	TaskID      string     `gorm:"size:100;uniqueIndex;not null" json:"task_id"`
	Type        string     `gorm:"size:50;not null;index" json:"type"`   // replay, fuzzing
	Target      string     `gorm:"size:500;not null" json:"target"`      // 目标地址或接口
	Status      string     `gorm:"size:50;not null;index" json:"status"` // running, completed, failed, stopped
	Progress    int        `json:"progress"`                             // 0-100
	Parameters  JSON       `gorm:"type:json" json:"parameters,omitempty"`
	Result      JSON       `gorm:"type:json" json:"result,omitempty"`
	UserID      string     `gorm:"size:100;index" json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// DefenseTask 防御任务
type DefenseTask struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	TaskID         string     `gorm:"size:100;uniqueIndex;not null" json:"task_id"`
	Type           string     `gorm:"size:50;not null;index" json:"type"`   // ids, firewall, filter
	Interface      string     `gorm:"size:100" json:"interface"`            // 监听接口
	Status         string     `gorm:"size:50;not null;index" json:"status"` // running, stopped
	Parameters     JSON       `gorm:"type:json" json:"parameters,omitempty"`
	EventsDetected int        `json:"events_detected"`                          // 检测到的事件数
	AlertsCount    int        `json:"alerts_count"`                             // 告警数
	BlocksCount    int        `json:"blocks_count"`                             // 阻断数
	RecentAlerts   JSON       `gorm:"type:json" json:"recent_alerts,omitempty"` // 最近的告警
	UserID         string     `gorm:"size:100;index" json:"user_id"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// ProtocolStat 协议统计
type ProtocolStat struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	SessionID   uint      `gorm:"index;not null" json:"session_id"`
	Protocol    string    `gorm:"size:50;not null;index" json:"protocol"`
	PacketCount int64     `json:"packet_count"`
	ByteCount   int64     `json:"byte_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ScanResult 扫描结果
type ScanResult struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	TaskID      uint      `gorm:"not null;index" json:"task_id"`
	ResultType  string    `gorm:"size:50;not null;index" json:"result_type"` // port, service, vulnerability, can_id, modbus_device, topology
	Target      string    `gorm:"size:500" json:"target,omitempty"`          // 目标（IP/接口/端口）
	Port        int       `json:"port,omitempty"`
	Protocol    string    `gorm:"size:20" json:"protocol,omitempty"`
	State       string    `gorm:"size:20" json:"state,omitempty"`
	Service     string    `gorm:"size:100" json:"service,omitempty"`
	Version     string    `gorm:"size:255" json:"version,omitempty"`
	Banner      string    `gorm:"type:text" json:"banner,omitempty"`
	VulnType    string    `gorm:"size:100" json:"vuln_type,omitempty"`
	Severity    string    `gorm:"size:20;index" json:"severity,omitempty"`
	Title       string    `gorm:"size:255" json:"title,omitempty"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	Solution    string    `gorm:"type:text" json:"solution,omitempty"`
	CVE         string    `gorm:"size:50" json:"cve,omitempty"`
	CVSS        float64   `json:"cvss,omitempty"`
	Details     JSON      `gorm:"type:json" json:"details,omitempty"` // 详细信息（CAN/Modbus 特定数据）
	ExtraData   JSON      `gorm:"type:json" json:"extra_data,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// JSON 自定义 JSON 类型
type JSON map[string]interface{}

func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, j)
}

// TableName 指定表名
func (CaptureSession) TableName() string {
	return "capture_sessions"
}

func (Packet) TableName() string {
	return "packets"
}

func (Vulnerability) TableName() string {
	return "vulnerabilities"
}

func (ScanTask) TableName() string {
	return "scan_tasks"
}

func (AttackLog) TableName() string {
	return "attack_logs"
}

func (ProtocolStat) TableName() string {
	return "protocol_stats"
}
