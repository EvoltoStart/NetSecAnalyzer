package capture

import (
	"io/ioutil"
	"strings"
)

// GetAvailableSerialPorts 获取可用的串口列表
func GetAvailableSerialPorts() ([]string, error) {
	var ports []string

	// 读取 /dev 目录下的串口设备
	files, err := ioutil.ReadDir("/dev")
	if err != nil {
		return []string{"/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyS0"}, nil // 返回默认列表
	}

	for _, file := range files {
		name := file.Name()
		// 匹配常见的串口设备名
		if strings.HasPrefix(name, "ttyUSB") ||
			strings.HasPrefix(name, "ttyACM") ||
			strings.HasPrefix(name, "ttyS") ||
			strings.HasPrefix(name, "ttyAMA") {
			ports = append(ports, "/dev/"+name)
		}
	}

	// 如果没有找到任何串口，返回默认列表
	if len(ports) == 0 {
		return []string{"/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyS0"}, nil
	}

	return ports, nil
}
