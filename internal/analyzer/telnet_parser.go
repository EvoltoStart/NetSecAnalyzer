package analyzer

import (
	"fmt"
	"netsecanalyzer/internal/models"
	"strings"
)

// TelnetParser Telnet 协议解析器
type TelnetParser struct{}

func (p *TelnetParser) GetName() string {
	return "Telnet"
}

func (p *TelnetParser) Parse(packet *models.Packet) (*ProtocolInfo, error) {
	if len(packet.Payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	if packet.DstPort != 23 && packet.SrcPort != 23 {
		return nil, fmt.Errorf("not Telnet port")
	}

	info := &ProtocolInfo{
		Protocol: "Telnet",
		Fields:   make(map[string]interface{}),
	}

	payload := packet.Payload

	// Telnet 命令以 IAC (0xFF) 开始
	hasCommand := false
	commandCount := 0

	for i := 0; i < len(payload); i++ {
		if payload[i] == 0xFF {
			hasCommand = true
			commandCount++
			if i+1 < len(payload) {
				cmd := payload[i+1]
				cmdName := getTelnetCommandName(cmd)
				info.Fields[fmt.Sprintf("command_%d", commandCount)] = cmdName
				i++ // 跳过命令字节
			}
		}
	}

	if hasCommand {
		info.Fields["command_count"] = commandCount
		info.Summary = fmt.Sprintf("Telnet: %d commands", commandCount)
	} else {
		// 数据传输
		data := strings.TrimSpace(string(payload))
		if len(data) > 50 {
			data = data[:50] + "..."
		}
		info.Fields["data"] = data
		info.Summary = fmt.Sprintf("Telnet Data: %s", data)
	}

	return info, nil
}

func getTelnetCommandName(cmd byte) string {
	commands := map[byte]string{
		241: "NOP",
		242: "Data Mark",
		243: "Break",
		244: "Interrupt Process",
		245: "Abort Output",
		246: "Are You There",
		247: "Erase Character",
		248: "Erase Line",
		249: "Go Ahead",
		250: "SB (Subnegotiation Begin)",
		251: "WILL",
		252: "WONT",
		253: "DO",
		254: "DONT",
		255: "IAC",
	}

	if name, exists := commands[cmd]; exists {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", cmd)
}
