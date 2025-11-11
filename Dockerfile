# 构建阶段
FROM golang:1.21-alpine AS builder

WORKDIR /build

# 安装必要的构建工具
RUN apk add --no-cache git make gcc musl-dev libpcap-dev

# 复制 go mod 文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 编译
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o netsecanalyzer cmd/server/main.go

# 运行阶段
FROM alpine:latest

WORKDIR /app

# 安装运行时依赖
RUN apk add --no-cache ca-certificates libpcap

# 从构建阶段复制二进制文件
COPY --from=builder /build/netsecanalyzer .
COPY --from=builder /build/configs ./configs

# 创建必要的目录
RUN mkdir -p /app/logs /app/uploads

# 暴露端口
EXPOSE 8080

# 运行
CMD ["./netsecanalyzer", "-config", "./configs/config.yaml"]
