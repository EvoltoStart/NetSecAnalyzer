package attack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"netsecanalyzer/pkg/logger"
	"strings"
	"time"
)

// Fuzzer 模糊测试器
type Fuzzer struct {
	Manager    *AttackManager
	rand       *rand.Rand
	httpClient *http.Client // 复用HTTP客户端
}

// NewFuzzer 创建 Fuzzer
func NewFuzzer(manager *AttackManager) *Fuzzer {
	return &Fuzzer{
		Manager: manager,
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false, // 启用连接复用
			},
		},
	}
}

// FuzzConfig Fuzzing 配置
type FuzzConfig struct {
	Target           string
	Port             int
	Protocol         string
	Template         []byte
	Iterations       int
	MutationRate     float64
	MutationStrategy string
	Timeout          time.Duration
	Concurrency      int
	AnomalyDetection []string
}

// FuzzResult Fuzzing 结果
type FuzzResult struct {
	Iteration    int                    `json:"iteration"`
	Payload      []byte                 `json:"payload"`
	Response     []byte                 `json:"response,omitempty"`
	Error        string                 `json:"error,omitempty"`
	ResponseTime int64                  `json:"response_time"` // 毫秒
	Anomaly      bool                   `json:"anomaly"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// Fuzz 执行模糊测试
func (f *Fuzzer) Fuzz(ctx context.Context, config *FuzzConfig) ([]*FuzzResult, error) {
	logger.GetLogger().Infof("Starting fuzzing: target=%s:%d, protocol=%s, iterations=%d",
		config.Target, config.Port, config.Protocol, config.Iterations)

	results := make([]*FuzzResult, 0, config.Iterations)

	for i := 0; i < config.Iterations; i++ {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Fuzzing stopped by context")
			return results, ctx.Err()
		default:
			// 生成变异后的 payload
			mutatedPayload := f.mutateWithStrategy(config.Template, config.MutationRate, config.MutationStrategy)

			// 发送并接收响应
			result := &FuzzResult{
				Iteration: i + 1,
				Payload:   mutatedPayload,
			}

			startTime := time.Now()
			response, err := f.sendPayload(config.Target, config.Port, config.Protocol, mutatedPayload, config.Timeout)
			result.ResponseTime = time.Since(startTime).Milliseconds() // 转换为毫秒

			if err != nil {
				result.Error = err.Error()
				result.Anomaly = true
			} else {
				result.Response = response
				result.Anomaly = f.detectAnomalyWithConfig(response, result.ResponseTime, config.AnomalyDetection)

				// 如果检测到异常，提取响应中的错误信息
				if result.Anomaly && len(response) > 0 {
					// 将响应内容作为错误信息（截取前200字符）
					errorMsg := string(response)
					if len(errorMsg) > 200 {
						errorMsg = errorMsg[:200] + "..."
					}
					result.Error = errorMsg
				}
			}

			results = append(results, result)

			if result.Anomaly {
				logger.GetLogger().Warnf("Anomaly detected in iteration %d", i+1)
			}

			// 限速
			if config.Timeout > 0 {
				time.Sleep(config.Timeout / 10)
			}
		}
	}

	logger.GetLogger().Infof("Fuzzing completed: %d iterations, %d anomalies",
		len(results), f.countAnomalies(results))

	return results, nil
}

// mutateWithStrategy 根据策略变异数据
func (f *Fuzzer) mutateWithStrategy(data []byte, rate float64, strategy string) []byte {
	switch strategy {
	case "bitflip":
		return f.mutateBitFlip(data, rate)
	case "byteflip":
		return f.mutateByteFlip(data, rate)
	case "boundary":
		return f.mutateBoundary(data, rate)
	case "random":
		return f.mutateRandom(data, rate)
	case "smart":
		fallthrough
	default:
		return f.mutateSmart(data, rate)
	}
}

// mutateBitFlip 位翻转变异
func (f *Fuzzer) mutateBitFlip(data []byte, rate float64) []byte {
	mutated := make([]byte, len(data))
	copy(mutated, data)

	for i := range mutated {
		if f.rand.Float64() < rate {
			// 翻转随机位
			bitPos := uint(f.rand.Intn(8))
			mutated[i] ^= byte(1 << bitPos)
		}
	}
	return mutated
}

// mutateByteFlip 字节翻转变异
func (f *Fuzzer) mutateByteFlip(data []byte, rate float64) []byte {
	mutated := make([]byte, len(data))
	copy(mutated, data)

	for i := range mutated {
		if f.rand.Float64() < rate {
			// 翻转整个字节
			mutated[i] = ^mutated[i]
		}
	}
	return mutated
}

// mutateBoundary 边界值变异
func (f *Fuzzer) mutateBoundary(data []byte, rate float64) []byte {
	mutated := make([]byte, len(data))
	copy(mutated, data)

	boundaryValues := []byte{0x00, 0x01, 0x7F, 0x80, 0xFF}
	for i := range mutated {
		if f.rand.Float64() < rate {
			mutated[i] = boundaryValues[f.rand.Intn(len(boundaryValues))]
		}
	}
	return mutated
}

// mutateRandom 随机变异
func (f *Fuzzer) mutateRandom(data []byte, rate float64) []byte {
	mutated := make([]byte, len(data))
	copy(mutated, data)

	for i := range mutated {
		if f.rand.Float64() < rate {
			mutated[i] = byte(f.rand.Intn(256))
		}
	}
	return mutated
}

// mutateSmart 智能变异（混合策略）
func (f *Fuzzer) mutateSmart(data []byte, rate float64) []byte {
	mutated := make([]byte, len(data))
	copy(mutated, data)

	for i := range mutated {
		if f.rand.Float64() < rate {
			// 随机选择变异策略
			strategy := f.rand.Intn(5)
			switch strategy {
			case 0: // 位翻转
				mutated[i] ^= byte(1 << uint(f.rand.Intn(8)))
			case 1: // 随机字节
				mutated[i] = byte(f.rand.Intn(256))
			case 2: // 边界值
				mutated[i] = []byte{0x00, 0xFF, 0x7F, 0x80}[f.rand.Intn(4)]
			case 3: // 增加
				mutated[i]++
			case 4: // 减少
				mutated[i]--
			}
		}
	}

	// 随机长度变异
	if f.rand.Float64() < 0.1 {
		action := f.rand.Intn(3)
		switch action {
		case 0: // 插入字节
			if len(mutated) > 0 {
				pos := f.rand.Intn(len(mutated))
				newByte := byte(f.rand.Intn(256))
				mutated = append(mutated[:pos], append([]byte{newByte}, mutated[pos:]...)...)
			}
		case 1: // 删除字节
			if len(mutated) > 1 {
				pos := f.rand.Intn(len(mutated))
				mutated = append(mutated[:pos], mutated[pos+1:]...)
			}
		case 2: // 重复字节
			if len(mutated) > 0 {
				pos := f.rand.Intn(len(mutated))
				repeat := f.rand.Intn(10) + 1
				for i := 0; i < repeat; i++ {
					mutated = append(mutated[:pos], append([]byte{mutated[pos]}, mutated[pos:]...)...)
				}
			}
		}
	}

	return mutated
}

// mutate 变异数据（保留用于兼容性）
func (f *Fuzzer) mutate(data []byte, rate float64) []byte {
	mutated := make([]byte, len(data))
	copy(mutated, data)

	for i := range mutated {
		if f.rand.Float64() < rate {
			// 随机选择变异策略
			strategy := f.rand.Intn(5)
			switch strategy {
			case 0: // 位翻转
				mutated[i] ^= byte(1 << uint(f.rand.Intn(8)))
			case 1: // 随机字节
				mutated[i] = byte(f.rand.Intn(256))
			case 2: // 边界值
				mutated[i] = []byte{0x00, 0xFF, 0x7F, 0x80}[f.rand.Intn(4)]
			case 3: // 增加
				mutated[i]++
			case 4: // 减少
				mutated[i]--
			}
		}
	}

	// 随机长度变异
	if f.rand.Float64() < 0.1 {
		action := f.rand.Intn(3)
		switch action {
		case 0: // 插入字节
			pos := f.rand.Intn(len(mutated))
			newByte := byte(f.rand.Intn(256))
			mutated = append(mutated[:pos], append([]byte{newByte}, mutated[pos:]...)...)
		case 1: // 删除字节
			if len(mutated) > 1 {
				pos := f.rand.Intn(len(mutated))
				mutated = append(mutated[:pos], mutated[pos+1:]...)
			}
		case 2: // 重复字节
			if len(mutated) > 0 {
				pos := f.rand.Intn(len(mutated))
				repeat := f.rand.Intn(10) + 1
				for i := 0; i < repeat; i++ {
					mutated = append(mutated[:pos], append([]byte{mutated[pos]}, mutated[pos:]...)...)
				}
			}
		}
	}

	return mutated
}

// sendPayload 发送 payload
func (f *Fuzzer) sendPayload(target string, port int, protocol string, payload []byte, timeout time.Duration) ([]byte, error) {
	// 根据协议发送数据
	address := fmt.Sprintf("%s:%d", target, port)

	switch protocol {
	case "TCP":
		return f.sendTCP(address, payload, timeout)
	case "UDP":
		return f.sendUDP(address, payload, timeout)
	case "HTTP":
		return f.sendHTTP(target, port, payload, timeout)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// sendTCP 发送 TCP 数据
func (f *Fuzzer) sendTCP(address string, payload []byte, timeout time.Duration) ([]byte, error) {
	logger.GetLogger().Debugf("Sending TCP payload to %s (%d bytes)", address, len(payload))

	// 建立 TCP 连接
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(timeout))

	// 发送数据
	_, err = conn.Write(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to send: %w", err)
	}

	// 接收响应
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		// 超时或连接关闭不算错误
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return response[:0], nil
		}
		if err.Error() == "EOF" {
			return response[:0], nil
		}
		return nil, fmt.Errorf("failed to receive: %w", err)
	}

	return response[:n], nil
}

// sendUDP 发送 UDP 数据
func (f *Fuzzer) sendUDP(address string, payload []byte, timeout time.Duration) ([]byte, error) {
	logger.GetLogger().Debugf("Sending UDP payload to %s (%d bytes)", address, len(payload))

	// 解析地址
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	// 建立 UDP 连接
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(timeout))

	// 发送数据
	_, err = conn.Write(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to send: %w", err)
	}

	// 接收响应
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		// 超时不算错误
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return response[:0], nil
		}
		return nil, fmt.Errorf("failed to receive: %w", err)
	}

	return response[:n], nil
}

// sendHTTP 发送 HTTP 请求
func (f *Fuzzer) sendHTTP(host string, port int, payload []byte, timeout time.Duration) ([]byte, error) {
	logger.GetLogger().Debugf("Sending HTTP payload to %s:%d (%d bytes)", host, port, len(payload))

	// 使用复用的HTTP客户端，但设置当前请求的超时
	client := f.httpClient
	if timeout > 0 && timeout != client.Timeout {
		// 如果超时不同，创建临时客户端
		client = &http.Client{
			Timeout:   timeout,
			Transport: f.httpClient.Transport,
		}
	}

	// 构建 URL
	url := fmt.Sprintf("http://%s:%d/", host, port)

	// 创建请求
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return response, nil
}

// detectAnomalyWithConfig 根据配置检测异常
func (f *Fuzzer) detectAnomalyWithConfig(response []byte, responseTimeMs int64, detectionConfig []string) bool {
	for _, check := range detectionConfig {
		switch check {
		case "timeout":
			// 响应时间过长 (超过5秒 = 5000毫秒)
			if responseTimeMs > 5000 {
				return true
			}
		case "error":
			// 响应包含错误标识
			errorKeywords := []string{"error", "exception", "crash", "fault"}
			responseStr := string(response)
			for _, keyword := range errorKeywords {
				if contains(responseStr, keyword) {
					return true
				}
			}
		case "crash":
			// 响应为空可能表示崩溃
			if len(response) == 0 {
				return true
			}
		case "memory":
			// 检测内存相关错误
			memoryKeywords := []string{"memory", "overflow", "segmentation", "heap"}
			responseStr := string(response)
			for _, keyword := range memoryKeywords {
				if contains(responseStr, keyword) {
					return true
				}
			}
		}
	}
	return false
}

// detectAnomaly 检测异常（保留用于兼容性）
func (f *Fuzzer) detectAnomaly(response []byte, responseTime time.Duration) bool {
	// 简单的异常检测逻辑
	// 1. 响应时间过长
	if responseTime > 5*time.Second {
		return true
	}

	// 2. 响应为空
	if len(response) == 0 {
		return true
	}

	// 3. 响应包含错误标识
	errorKeywords := []string{"error", "exception", "crash", "fault"}
	responseStr := string(response)
	for _, keyword := range errorKeywords {
		if contains(responseStr, keyword) {
			return true
		}
	}

	return false
}

// countAnomalies 统计异常数量
func (f *Fuzzer) countAnomalies(results []*FuzzResult) int {
	count := 0
	for _, result := range results {
		if result.Anomaly {
			count++
		}
	}
	return count
}

// contains 简单的字符串包含检查
func contains(str, substr string) bool {
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}

// GenerateFuzzTemplates 生成模糊测试模板
func (f *Fuzzer) GenerateFuzzTemplates(protocol string) [][]byte {
	templates := [][]byte{}

	switch protocol {
	case "HTTP":
		templates = append(templates, []byte("GET / HTTP/1.1\r\nHost: target\r\n\r\n"))
		templates = append(templates, []byte("POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n"))
	case "Modbus":
		// Modbus 读取保持寄存器
		templates = append(templates, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A})
	case "FTP":
		templates = append(templates, []byte("USER anonymous\r\n"))
		templates = append(templates, []byte("PASS guest\r\n"))
	}

	return templates
}
