# NetSecAnalyzer - 网络安全分析系统

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Vue Version](https://img.shields.io/badge/Vue-3.3+-brightgreen.svg)](https://vuejs.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 项目简介

NetSecAnalyzer 是一套基于 Go 和 Vue 的网络/总线数据采集、协议分析、漏洞扫描与攻防系统。支持 IP 网络、CAN 总线和 RS-485 串口三类数据源的采集与分析。

## 核心功能

### 1. 数据采集
- **IP 网络采集**：基于 libpcap/gopacket 实现以太网数据包捕获
  - 支持 BPF 过滤器
  - 实时流量监控
  - PCAP 文件导入/导出

- **CAN 总线采集**：基于 SocketCAN 实现 CAN 帧采集
  - 支持标准/扩展 CAN 帧
  - 实时总线监控
  - CAN 帧发送功能

- **RS-485 采集**：基于串口通信实现 Modbus 等协议采集
  - Modbus RTU/TCP 支持
  - 自定义串口协议
  - 寄存器读写功能

### 2. 协议分析
支持多种网络和工控协议的深度解析：
- **网络协议**：HTTP/HTTPS, DNS, FTP, Telnet, SSH, SMTP
- **工控协议**：Modbus TCP/RTU, S7, DNP3
- **传输协议**：TCP, UDP, ICMP
- **CAN 协议**：OBD-II, J1939, CANopen

### 3. 漏洞扫描
- 端口扫描（SYN/Connect/UDP）
- 服务识别与指纹识别
- 弱密码检测
- 已知漏洞匹配（CVE 数据库）
- 配置错误检测

### 4. 攻防模拟
- 数据包重放（PCAP 回放）
- 协议 Fuzzing（模糊测试）
- 数据包修改与重放
- 操作审计与日志记录

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    前端层 (Vue 3 + Element Plus)             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ 数据采集 │  │ 协议分析 │  │ 漏洞扫描 │  │ 攻防模拟 │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└───────────────────────┬─────────────────────────────────────┘
                        │ RESTful API / WebSocket
┌───────────────────────┴─────────────────────────────────────┐
│                    API 网关层 (Gin)                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────┴─────────────────────────────────────┐
│                      业务逻辑层 (Go)                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐│
│  │  数据采集       │  │  协议分析       │  │ 漏洞扫描    ││
│  │  攻防模拟       │  │  数据库         │  │ 日志系统    ││
│  └─────────────────┘  └─────────────────┘  └─────────────┘│
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────┴─────────────────────────────────────┐
│              数据采集层 (gopacket/SocketCAN/Serial)         │
└─────────────────────────────────────────────────────────────┘
```

## 技术栈

### 后端
- **语言**：Go 1.21+
- **Web 框架**：Gin
- **数据库**：MySQL 8.0+ (GORM)
- **缓存**：Redis
- **数据包处理**：gopacket, libpcap
- **串口通信**：tarm/serial, goburrow/modbus
- **日志**：logrus, lumberjack
- **配置**：viper

### 前端
- **框架**：Vue 3
- **构建工具**：Vite
- **UI 库**：Element Plus
- **图表**：ECharts
- **HTTP 客户端**：Axios
- **状态管理**：Pinia
- **路由**：Vue Router

## 快速开始

### 环境要求

- Go 1.21 或更高版本
- Node.js 16+ 和 npm
- MySQL 8.0+
- Redis (可选)
- Linux 操作系统（用于数据包捕获需要 root 权限）

### 安装依赖

#### 后端依赖

```bash
# 安装 libpcap 开发库
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# 下载 Go 依赖
cd /home/meng/Projects/GolandProjects/NetSecAnalyzer
go mod download
```

#### 前端依赖

```bash
cd frontend
npm install
```

### 配置

编辑 `configs/config.yaml` 配置文件：

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  mode: "debug"

database:
  host: "localhost"
  port: 3306
  user: "root"
  password: "your_password"
  dbname: "netsecanalyzer"

capture:
  ip:
    interface: "eth0"  # 修改为你的网络接口
  can:
    interface: "can0"  # 修改为你的 CAN 接口
  rs485:
    port: "/dev/ttyUSB0"  # 修改为你的串口设备
```

### 数据库初始化

```sql
CREATE DATABASE netsecanalyzer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

数据库表会在首次启动时自动创建。

### 运行

#### 方式一：直接运行

```bash
# 后端
make run
# 或
go run cmd/server/main.go -config ./configs/config.yaml

# 前端（新终端）
cd frontend
npm run dev
```

#### 方式二：使用 Docker Compose

```bash
# 构建并启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

### 访问

- 前端界面：http://localhost:3000
- 后端 API：http://localhost:8080
- API 文档：http://localhost:8080/api/health

## 使用说明

### 1. 数据采集

1. 进入"数据采集"页面
2. 选择采集类型（IP/CAN/RS485）
3. 配置采集参数（接口、过滤器等）
4. 点击"开始采集"
5. 查看实时数据流和统计信息

### 2. 协议分析

1. 进入"协议分析"页面
2. 选择要分析的会话
3. 查看协议分布和统计图表
4. 深入查看特定协议的详细信息

### 3. 漏洞扫描

1. 进入"漏洞扫描"页面
2. 输入目标 IP 地址或域名
3. 配置端口范围和扫描类型
4. 启动扫描任务
5. 查看扫描结果和发现的漏洞

### 4. 攻防模拟

**警告：攻防功能仅供授权测试使用！**

1. 进入"攻防模拟"页面
2. 选择攻击模式：
   - 数据包重放：回放历史流量
   - 协议 Fuzzing：模糊测试目标服务
3. 配置攻击参数
4. 确认已获得授权后启动
5. 查看攻击结果和日志

## 项目结构

```
NetSecAnalyzer/
├── cmd/
│   └── server/
│       └── main.go              # 主程序入口
├── internal/
│   ├── api/                     # API 处理器
│   │   ├── router.go
│   │   ├── capture_handler.go
│   │   ├── analyze_handler.go
│   │   ├── scan_handler.go
│   │   └── attack_handler.go
│   ├── capture/                 # 数据采集模块
│   │   ├── ip_capture.go
│   │   ├── can_capture.go
│   │   └── rs485_capture.go
│   ├── analyzer/                # 协议分析模块
│   │   ├── analyzer.go
│   │   ├── http_parser.go
│   │   ├── modbus_parser.go
│   │   └── ...
│   ├── scanner/                 # 漏洞扫描模块
│   │   └── scanner.go
│   ├── attack/                  # 攻防模拟模块
│   │   ├── attack.go
│   │   ├── replay.go
│   │   └── fuzzer.go
│   ├── models/                  # 数据模型
│   │   └── models.go
│   ├── database/                # 数据库
│   │   └── database.go
│   ├── config/                  # 配置管理
│   │   └── config.go
│   └── middleware/              # 中间件
│       └── middleware.go
├── pkg/
│   ├── logger/                  # 日志工具
│   │   └── logger.go
│   └── utils/                   # 工具函数
│       └── utils.go
├── frontend/                    # Vue 前端
│   ├── src/
│   │   ├── views/               # 页面组件
│   │   ├── router/              # 路由配置
│   │   ├── App.vue
│   │   └── main.js
│   ├── package.json
│   └── vite.config.js
├── configs/
│   └── config.yaml              # 配置文件
├── docker-compose.yml           # Docker Compose 配置
├── Dockerfile                   # Docker 镜像
├── Makefile                     # 构建脚本
├── go.mod
├── go.sum
├── ARCHITECTURE.md              # 架构设计文档
└── README.md                    # 本文件
```

## 开发指南

### 编译

```bash
# 编译后端
make build

# 编译前端
make frontend

# 清理构建
make clean
```

### 测试

```bash
# 运行单元测试
make test

# 代码格式化
make fmt

# 代码检查
make lint
```

### 添加新的协议解析器

1. 在 `internal/analyzer/` 创建新的解析器文件
2. 实现 `ProtocolParser` 接口
3. 在 `analyzer.go` 中注册解析器

```go
// 示例：custom_parser.go
type CustomParser struct{}

func (p *CustomParser) GetName() string {
    return "CustomProtocol"
}

func (p *CustomParser) Parse(packet *models.Packet) (*ProtocolInfo, error) {
    // 实现解析逻辑
    return &ProtocolInfo{
        Protocol: "CustomProtocol",
        Summary:  "...",
    }, nil
}

// 在 NewAnalyzer() 中注册
a.RegisterParser(&CustomParser{})
```

## 安全注意事项

1. **权限要求**：数据包捕获需要 `CAP_NET_RAW` 和 `CAP_NET_ADMIN` 权限
2. **授权测试**：攻防功能仅供授权测试，所有操作会被记录
3. **数据保护**：敏感数据（如密码）会自动脱敏处理
4. **网络隔离**：建议在隔离的测试网络中运行
5. **日志审计**：定期检查操作日志，防止滥用

## 性能优化

- 使用缓冲区和批量写入减少数据库 I/O
- 数据包处理采用多协程并发
- 前端使用虚拟滚动处理大数据量
- 数据库索引优化和分表策略
- Redis 缓存热点数据

## 常见问题

**Q: 提示 "permission denied" 错误？**
A: 数据包捕获需要 root 权限，使用 `sudo` 运行或设置 capabilities：
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./build/netsecanalyzer
```

**Q: CAN 接口无法使用？**
A: 确保已加载 CAN 模块并配置接口：
```bash
sudo modprobe can
sudo modprobe can_raw
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up
```

**Q: 前端无法连接后端？**
A: 检查 CORS 配置和代理设置，确保 `vite.config.js` 中的代理地址正确。

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- 项目主页：https://github.com/yourusername/NetSecAnalyzer
- 问题反馈：https://github.com/yourusername/NetSecAnalyzer/issues

## 致谢

感谢以下开源项目：
- [gopacket](https://github.com/google/gopacket)
- [Gin](https://github.com/gin-gonic/gin)
- [Vue.js](https://github.com/vuejs/vue)
- [Element Plus](https://github.com/element-plus/element-plus)
- [GORM](https://github.com/go-gorm/gorm)

---

**免责声明**：本工具仅供学习研究和授权测试使用，使用者应遵守相关法律法规，不得用于非法用途。使用本工具产生的一切后果由使用者自行承担。
