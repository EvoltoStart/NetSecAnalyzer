package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"netsecanalyzer/internal/models"
	"netsecanalyzer/pkg/logger"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Exporter 数据导出器
type Exporter struct {
	outputDir string
}

// NewExporter 创建导出器
func NewExporter(outputDir string) *Exporter {
	// 确保输出目录存在
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.GetLogger().Errorf("Failed to create output directory: %v", err)
	}
	return &Exporter{
		outputDir: outputDir,
	}
}

// ExportToPCAP 导出为 PCAP 文件
func (e *Exporter) ExportToPCAP(packets []*models.Packet, filename string) (string, error) {
	if len(packets) == 0 {
		return "", fmt.Errorf("no packets to export")
	}

	filepath := fmt.Sprintf("%s/%s", e.outputDir, filename)
	f, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	// 创建 PCAP 写入器
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return "", fmt.Errorf("failed to write pcap header: %w", err)
	}

	logger.GetLogger().Infof("Exporting %d packets to PCAP: %s", len(packets), filepath)

	// 写入数据包
	for i, pkt := range packets {
		// 构造 PCAP 数据包
		captureInfo := gopacket.CaptureInfo{
			Timestamp:     pkt.Timestamp,
			CaptureLength: int(pkt.Length),
			Length:        int(pkt.Length),
		}

		// 如果有 Payload，直接写入
		if len(pkt.Payload) > 0 {
			if err := w.WritePacket(captureInfo, pkt.Payload); err != nil {
				logger.GetLogger().Warnf("Failed to write packet %d: %v", i, err)
				continue
			}
		} else {
			// 如果没有 Payload，构造一个简单的以太网帧
			// 这种情况下只能保存基本信息
			eth := &layers.Ethernet{
				SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				EthernetType: layers.EthernetTypeIPv4,
			}

			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{}
			if err := gopacket.SerializeLayers(buf, opts, eth); err != nil {
				logger.GetLogger().Warnf("Failed to serialize packet %d: %v", i, err)
				continue
			}

			if err := w.WritePacket(captureInfo, buf.Bytes()); err != nil {
				logger.GetLogger().Warnf("Failed to write packet %d: %v", i, err)
				continue
			}
		}
	}

	logger.GetLogger().Infof("Successfully exported %d packets to %s", len(packets), filepath)
	return filepath, nil
}

// ExportToCSV 导出为 CSV 文件
func (e *Exporter) ExportToCSV(packets []*models.Packet, filename string) (string, error) {
	if len(packets) == 0 {
		return "", fmt.Errorf("no packets to export")
	}

	filepath := fmt.Sprintf("%s/%s", e.outputDir, filename)
	f, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	logger.GetLogger().Infof("Exporting %d packets to CSV: %s", len(packets), filepath)

	// 写入表头
	header := []string{
		"ID", "SessionID", "Timestamp", "Protocol", "SrcAddr", "SrcPort",
		"DstAddr", "DstPort", "Length", "PayloadHash",
	}
	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("failed to write header: %w", err)
	}

	// 写入数据
	for _, pkt := range packets {
		record := []string{
			fmt.Sprintf("%d", pkt.ID),
			fmt.Sprintf("%d", pkt.SessionID),
			pkt.Timestamp.Format(time.RFC3339Nano),
			pkt.Protocol,
			pkt.SrcAddr,
			fmt.Sprintf("%d", pkt.SrcPort),
			pkt.DstAddr,
			fmt.Sprintf("%d", pkt.DstPort),
			fmt.Sprintf("%d", pkt.Length),
			pkt.PayloadHash,
		}
		if err := writer.Write(record); err != nil {
			logger.GetLogger().Warnf("Failed to write packet %d: %v", pkt.ID, err)
			continue
		}
	}

	logger.GetLogger().Infof("Successfully exported %d packets to %s", len(packets), filepath)
	return filepath, nil
}

// ExportToJSON 导出为 JSON 文件
func (e *Exporter) ExportToJSON(packets []*models.Packet, filename string) (string, error) {
	if len(packets) == 0 {
		return "", fmt.Errorf("no packets to export")
	}

	filepath := fmt.Sprintf("%s/%s", e.outputDir, filename)
	f, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	logger.GetLogger().Infof("Exporting %d packets to JSON: %s", len(packets), filepath)

	// 创建导出数据结构
	exportData := struct {
		ExportTime  time.Time        `json:"export_time"`
		PacketCount int              `json:"packet_count"`
		Packets     []*models.Packet `json:"packets"`
	}{
		ExportTime:  time.Now(),
		PacketCount: len(packets),
		Packets:     packets,
	}

	// 编码为 JSON
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(exportData); err != nil {
		return "", fmt.Errorf("failed to encode JSON: %w", err)
	}

	logger.GetLogger().Infof("Successfully exported %d packets to %s", len(packets), filepath)
	return filepath, nil
}

// ExportSessionToPCAP 导出会话为 PCAP
func (e *Exporter) ExportSessionToPCAP(session *models.CaptureSession, packets []*models.Packet) (string, error) {
	filename := fmt.Sprintf("session_%d_%s.pcap", session.ID, time.Now().Format("20060102_150405"))
	return e.ExportToPCAP(packets, filename)
}

// ExportSessionToCSV 导出会话为 CSV
func (e *Exporter) ExportSessionToCSV(session *models.CaptureSession, packets []*models.Packet) (string, error) {
	filename := fmt.Sprintf("session_%d_%s.csv", session.ID, time.Now().Format("20060102_150405"))
	return e.ExportToCSV(packets, filename)
}

// ExportSessionToJSON 导出会话为 JSON
func (e *Exporter) ExportSessionToJSON(session *models.CaptureSession, packets []*models.Packet) (string, error) {
	filename := fmt.Sprintf("session_%d_%s.json", session.ID, time.Now().Format("20060102_150405"))
	return e.ExportToJSON(packets, filename)
}

// ExportScanResultToJSON 导出扫描结果为 JSON
func (e *Exporter) ExportScanResultToJSON(task *models.ScanTask, results []*models.ScanResult) (string, error) {
	filename := fmt.Sprintf("scan_task_%d_%s.json", task.ID, time.Now().Format("20060102_150405"))
	filepath := fmt.Sprintf("%s/%s", e.outputDir, filename)

	f, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	logger.GetLogger().Infof("Exporting scan results to JSON: %s", filepath)

	// 创建导出数据结构
	exportData := struct {
		ExportTime  time.Time            `json:"export_time"`
		Task        *models.ScanTask     `json:"task"`
		ResultCount int                  `json:"result_count"`
		Results     []*models.ScanResult `json:"results"`
	}{
		ExportTime:  time.Now(),
		Task:        task,
		ResultCount: len(results),
		Results:     results,
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(exportData); err != nil {
		return "", fmt.Errorf("failed to encode JSON: %w", err)
	}

	logger.GetLogger().Infof("Successfully exported scan results to %s", filepath)
	return filepath, nil
}

// ExportScanResultToCSV 导出扫描结果为 CSV
func (e *Exporter) ExportScanResultToCSV(task *models.ScanTask, results []*models.ScanResult) (string, error) {
	filename := fmt.Sprintf("scan_task_%d_%s.csv", task.ID, time.Now().Format("20060102_150405"))
	filepath := fmt.Sprintf("%s/%s", e.outputDir, filename)

	f, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	logger.GetLogger().Infof("Exporting scan results to CSV: %s", filepath)

	// 写入表头
	header := []string{
		"ID", "Type", "Port", "Protocol", "Service", "Version",
		"VulnType", "Severity", "Title", "CVE", "CVSS",
	}
	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("failed to write header: %w", err)
	}

	// 写入数据
	for _, result := range results {
		record := []string{
			fmt.Sprintf("%d", result.ID),
			result.ResultType,
			fmt.Sprintf("%d", result.Port),
			result.Protocol,
			result.Service,
			result.Version,
			result.VulnType,
			result.Severity,
			result.Title,
			result.CVE,
			fmt.Sprintf("%.1f", result.CVSS),
		}
		if err := writer.Write(record); err != nil {
			logger.GetLogger().Warnf("Failed to write result %d: %v", result.ID, err)
			continue
		}
	}

	logger.GetLogger().Infof("Successfully exported scan results to %s", filepath)
	return filepath, nil
}
