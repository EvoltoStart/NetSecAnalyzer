package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"netsecanalyzer/internal/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	// 连接数据库
	dsn := "root:root@tcp(localhost:3306)/netsecanalyzer?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// 创建测试会话
	session := &models.CaptureSession{
		Name:        "测试会话 - 模拟流量",
		Type:        "ip",
		Status:      "completed",
		PacketCount: 0,
	}
	now := time.Now()
	session.StartTime = &now
	endTime := now.Add(5 * time.Minute)
	session.EndTime = &endTime

	if err := db.Create(session).Error; err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	fmt.Printf("Created test session with ID: %d\n", session.ID)

	// 生成测试数据包
	protocols := []string{"HTTP", "DNS", "TCP", "UDP", "ICMP", "ARP", "TLS", "SSH"}
	srcIPs := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50"}
	dstIPs := []string{"8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"}

	rand.Seed(time.Now().UnixNano())

	packetCount := 1000
	fmt.Printf("Generating %d test packets...\n", packetCount)

	for i := 0; i < packetCount; i++ {
		protocol := protocols[rand.Intn(len(protocols))]
		srcIP := srcIPs[rand.Intn(len(srcIPs))]
		dstIP := dstIPs[rand.Intn(len(dstIPs))]
		srcPort := rand.Intn(60000) + 1024
		dstPort := getPortForProtocol(protocol)
		length := rand.Intn(1400) + 60

		// 生成随机 payload
		payload := make([]byte, rand.Intn(100)+20)
		rand.Read(payload)

		packet := &models.Packet{
			SessionID: session.ID,
			Timestamp: now.Add(time.Duration(i) * time.Millisecond * 50),
			SrcAddr:   srcIP,
			SrcPort:   srcPort,
			DstAddr:   dstIP,
			DstPort:   dstPort,
			Protocol:  protocol,
			Length:    length,
			Payload:   payload,
			AnalysisResult: models.JSON{
				"protocol": protocol,
				"summary":  fmt.Sprintf("%s: %s:%d -> %s:%d (%d bytes)", protocol, srcIP, srcPort, dstIP, dstPort, length),
			},
		}

		if err := db.Create(packet).Error; err != nil {
			log.Printf("Failed to create packet %d: %v", i, err)
		}

		if (i+1)%100 == 0 {
			fmt.Printf("Generated %d packets...\n", i+1)
		}
	}

	// 更新会话的数据包计数
	session.PacketCount = int64(packetCount)
	db.Save(session)

	fmt.Printf("\n✅ Successfully generated %d test packets for session %d\n", packetCount, session.ID)
	fmt.Println("You can now view the protocol analysis page to see the data!")
}

func getPortForProtocol(protocol string) int {
	portMap := map[string]int{
		"HTTP":  80,
		"HTTPS": 443,
		"DNS":   53,
		"SSH":   22,
		"FTP":   21,
		"TLS":   443,
		"TCP":   rand.Intn(60000) + 1024,
		"UDP":   rand.Intn(60000) + 1024,
		"ICMP":  0,
		"ARP":   0,
	}

	if port, ok := portMap[protocol]; ok {
		return port
	}
	return rand.Intn(60000) + 1024
}
