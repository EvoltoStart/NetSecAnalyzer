.PHONY: all build run clean test docker frontend help

# 项目名称
APP_NAME = netsecanalyzer
VERSION = 1.0.0
BUILD_DIR = ./build
FRONTEND_DIR = ./frontend

# Go 参数
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST = $(GOCMD) test
GOGET = $(GOCMD) get
GOMOD = $(GOCMD) mod

# 构建参数
LDFLAGS = -ldflags "-X main.Version=$(VERSION)"

all: build

## build: 编译项目
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) cmd/server/main.go
	@echo "Build complete: $(BUILD_DIR)/$(APP_NAME)"

## run: 运行服务器
run: build
	@echo "Running $(APP_NAME)..."
	$(BUILD_DIR)/$(APP_NAME) -config ./configs/config.yaml

## clean: 清理构建文件
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(FRONTEND_DIR)/dist
	@echo "Clean complete"

## test: 运行测试
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## deps: 安装依赖
deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies installed"

## frontend: 构建前端
frontend:
	@echo "Building frontend..."
	cd $(FRONTEND_DIR) && npm install && npm run build
	@echo "Frontend build complete"

## docker: 构建 Docker 镜像
docker:
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):$(VERSION) .
	@echo "Docker image built: $(APP_NAME):$(VERSION)"

## docker-run: 运行 Docker 容器
docker-run:
	docker-compose up -d

## docker-stop: 停止 Docker 容器
docker-stop:
	docker-compose down

## lint: 代码检查
lint:
	@echo "Running linter..."
	golangci-lint run ./...

## fmt: 格式化代码
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

## help: 显示帮助信息
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
