package ids

import "time"

// Detector 检测器接口
type Detector interface {
	Detect(info *PacketInfo) *Alert
	GetName() string
}

// PacketInfo 数据包信息
type PacketInfo struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	TCPFlags  string
	Length    int
	Payload   string
}
