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
	PacketCount int64      `json:"packetCount"`
	StartTime   *time.Time `json:"startTime,omitempty"`
	EndTime     *time.Time `json:"endTime,omitempty"`
	Config      JSON       `gorm:"type:text" json:"config"` // SQLite 兼容: json → text
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// Packet 数据包
type Packet struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	SessionID      uint      `gorm:"index;not null" json:"sessionId"`
	Timestamp      time.Time `gorm:"index" json:"timestamp"`
	Protocol       string    `gorm:"size:50;index" json:"protocol"`
	SrcAddr        string    `gorm:"size:100;index" json:"srcAddr"`
	DstAddr        string    `gorm:"size:100;index" json:"dstAddr"`
	SrcPort        int       `json:"srcPort,omitempty"`
	DstPort        int       `json:"dstPort,omitempty"`
	Length         int       `json:"length"`
	Payload        []byte    `gorm:"type:blob" json:"payload,omitempty"`         // 应用层数据
	RawData        []byte    `gorm:"type:blob" json:"rawData,omitempty"`         // 完整的原始数据包（用于重放）
	PayloadPath    string    `gorm:"size:500" json:"payloadPath,omitempty"`      // Payload 文件路径
	PayloadHash    string    `gorm:"size:64;index" json:"payloadHash,omitempty"` // Payload SHA256 哈希
	AnalysisResult JSON      `gorm:"type:text" json:"analysisResult,omitempty"`  // SQLite 兼容: json → text
	CreatedAt      time.Time `json:"createdAt"`
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Target       string    `gorm:"size:255;not null;index" json:"target"`
	Port         int       `json:"port,omitempty"` // 端口号
	VulnType     string    `gorm:"size:100;not null" json:"vulnType"`
	Severity     string    `gorm:"size:50;not null;index" json:"severity"` // critical, high, medium, low, info
	CVEID        string    `gorm:"size:50;index" json:"cveId,omitempty"`
	CVSS         float64   `json:"cvss,omitempty"` // CVSS 评分
	Title        string    `gorm:"size:500" json:"title"`
	Description  string    `gorm:"type:text" json:"description"`
	Solution     string    `gorm:"type:text" json:"solution,omitempty"`
	References   JSON      `gorm:"type:text" json:"references,omitempty"` // SQLite 兼容: json → text
	DiscoveredAt time.Time `json:"discoveredAt"`
	CreatedAt    time.Time `json:"createdAt"`
}

// ScanTask 扫描任务
type ScanTask struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:255;not null" json:"name"`
	Target      string     `gorm:"size:500;not null" json:"target"`
	ScanType    string     `gorm:"size:50;not null" json:"scanType"`      // port, vuln, service, can, rs485
	NetworkType string     `gorm:"size:50;default:ip" json:"networkType"` // ip, can, rs485
	Status      string     `gorm:"size:50;not null;index" json:"status"`  // pending, running, completed, failed
	Progress    int        `json:"progress"`                              // 0-100
	Result      JSON       `gorm:"type:text" json:"result,omitempty"`     // SQLite 兼容: json → text
	Error       string     `gorm:"type:text" json:"error,omitempty"`
	StartTime   *time.Time `json:"startTime,omitempty"`
	EndTime     *time.Time `json:"endTime,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// AttackLog 攻击操作日志
type AttackLog struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	AttackType string    `gorm:"size:100;not null;index" json:"attackType"`
	Target     string    `gorm:"size:500;not null" json:"target"`
	Method     string    `gorm:"size:100" json:"method"`
	Parameters JSON      `gorm:"type:text" json:"parameters,omitempty"` // SQLite 兼容: json → text
	Result     string    `gorm:"type:text" json:"result,omitempty"`
	Status     string    `gorm:"size:50;not null" json:"status"` // success, failed
	UserID     string    `gorm:"size:100;index" json:"userId"`
	Authorized bool      `gorm:"not null" json:"authorized"`
	ExecutedAt time.Time `gorm:"index" json:"executedAt"`
	CreatedAt  time.Time `json:"createdAt"`
}

// AttackTask 攻击任务
type AttackTask struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	TaskID      string     `gorm:"size:100;uniqueIndex:uni_attack_tasks_task_id;not null" json:"taskId"`
	Type        string     `gorm:"size:50;not null;index" json:"type"`    // replay, fuzzing
	Target      string     `gorm:"size:500;not null" json:"target"`       // 目标地址或接口
	Status      string     `gorm:"size:50;not null;index" json:"status"`  // running, completed, failed, stopped
	Progress    int        `json:"progress"`                              // 0-100
	Parameters  JSON       `gorm:"type:text" json:"parameters,omitempty"` // SQLite 兼容: json → text
	Result      JSON       `gorm:"type:text" json:"result,omitempty"`     // SQLite 兼容: json → text
	UserID      string     `gorm:"size:100;index" json:"userId"`
	CreatedAt   time.Time  `json:"createdAt"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

// DefenseTask 防御任务
type DefenseTask struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	TaskID         string     `gorm:"size:100;uniqueIndex:uni_defense_tasks_task_id;not null" json:"taskId"`
	Type           string     `gorm:"size:50;not null;index" json:"type"`      // ids, firewall, filter
	Interface      string     `gorm:"size:100" json:"interface"`               // 监听接口
	Status         string     `gorm:"size:50;not null;index" json:"status"`    // running, stopped
	Parameters     JSON       `gorm:"type:text" json:"parameters,omitempty"`   // SQLite 兼容: json → text
	EventsDetected int        `json:"eventsDetected"`                          // 检测到的事件数
	AlertsCount    int        `json:"alertsCount"`                             // 告警数
	BlocksCount    int        `json:"blocksCount"`                             // 阻断数
	RecentAlerts   JSON       `gorm:"type:text" json:"recentAlerts,omitempty"` // SQLite 兼容: json → text
	UserID         string     `gorm:"size:100;index" json:"userId"`
	CreatedAt      time.Time  `json:"createdAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

// IDSAlert IDS 告警记录
type IDSAlert struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	TaskID          uint       `gorm:"not null;index" json:"taskId"`                              // 关联的 defense_task ID
	Type            string     `gorm:"size:50;not null;index" json:"type"`                        // 告警类型
	Severity        string     `gorm:"size:20;not null;index" json:"severity"`                    // 严重程度
	Description     string     `gorm:"type:text;not null" json:"description"`                     // 告警描述
	Source          string     `gorm:"size:100;index" json:"source,omitempty"`                    // 攻击来源 IP
	Destination     string     `gorm:"size:100" json:"destination,omitempty"`                     // 攻击目标 IP
	SourcePort      *int       `json:"sourcePort,omitempty"`                                      // 源端口
	DestinationPort *int       `json:"destinationPort,omitempty"`                                 // 目标端口
	Protocol        string     `gorm:"size:20" json:"protocol,omitempty"`                         // 协议
	Details         JSON       `gorm:"type:text" json:"details,omitempty"`                        // 详细信息
	Status          string     `gorm:"size:20;default:new;index" json:"status"`                   // 状态: new, acknowledged, resolved, ignored
	AcknowledgedBy  string     `gorm:"size:100" json:"acknowledgedBy,omitempty"`                  // 确认人
	AcknowledgedAt  *time.Time `json:"acknowledgedAt,omitempty"`                                  // 确认时间
	ResolvedBy      string     `gorm:"size:100" json:"resolvedBy,omitempty"`                      // 解决人
	ResolvedAt      *time.Time `json:"resolvedAt,omitempty"`                                      // 解决时间
	Notes           string     `gorm:"type:text" json:"notes,omitempty"`                          // 备注
	Timestamp       time.Time  `gorm:"not null;index:idx_ids_alerts_timestamp" json:"timestamp"`  // 告警发生时间
	CreatedAt       time.Time  `gorm:"not null;index:idx_ids_alerts_created_at" json:"createdAt"` // 创建时间
}

// ProtocolStat 协议统计
type ProtocolStat struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	SessionID   uint      `gorm:"index;not null" json:"sessionId"`
	Protocol    string    `gorm:"size:50;not null;index" json:"protocol"`
	PacketCount int64     `json:"packetCount"`
	ByteCount   int64     `json:"byteCount"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ScanResult 扫描结果
type ScanResult struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	TaskID       uint       `gorm:"not null;index" json:"taskId"`
	ResultType   string     `gorm:"size:50;not null;index" json:"resultType"` // port, service, vulnerability, can_id, modbus_device, topology
	Target       string     `gorm:"size:500" json:"target,omitempty"`         // 目标（IP/接口/端口）
	Port         int        `json:"port,omitempty"`
	Protocol     string     `gorm:"size:20" json:"protocol,omitempty"`
	State        string     `gorm:"size:20" json:"state,omitempty"`
	Service      string     `gorm:"size:100" json:"service,omitempty"`
	Version      string     `gorm:"size:255" json:"version,omitempty"`
	Banner       string     `gorm:"type:text" json:"banner,omitempty"`
	VulnType     string     `gorm:"size:100" json:"vulnType,omitempty"`
	Severity     string     `gorm:"size:20;index" json:"severity,omitempty"`
	Title        string     `gorm:"size:255" json:"title,omitempty"`
	Description  string     `gorm:"type:text" json:"description,omitempty"`
	Solution     string     `gorm:"type:text" json:"solution,omitempty"`
	CVE          string     `gorm:"size:50" json:"cve,omitempty"`
	CVSS         float64    `json:"cvss,omitempty"`
	Details      JSON       `gorm:"type:text" json:"details,omitempty"`   // SQLite 兼容: json → text
	ExtraData    JSON       `gorm:"type:text" json:"extraData,omitempty"` // SQLite 兼容: json → text
	DiscoveredAt *time.Time `json:"discoveredAt,omitempty"`               // 漏洞发现时间
	CreatedAt    time.Time  `json:"createdAt"`
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

func (IDSAlert) TableName() string {
	return "ids_alerts"
}
