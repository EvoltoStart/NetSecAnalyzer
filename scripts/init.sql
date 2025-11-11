-- NetSecAnalyzer 数据库初始化脚本
-- 创建数据库
CREATE DATABASE IF NOT EXISTS netsecanalyzer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE netsecanalyzer;

-- 1. 数据采集会话表
CREATE TABLE IF NOT EXISTS capture_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL COMMENT '会话名称',
    type VARCHAR(50) NOT NULL COMMENT '采集类型: ip, can, rs485',
    status VARCHAR(50) NOT NULL COMMENT '状态: running, stopped, completed',
    packet_count BIGINT DEFAULT 0 COMMENT '数据包数量',
    start_time DATETIME NOT NULL COMMENT '开始时间',
    end_time DATETIME NULL COMMENT '结束时间',
    config JSON COMMENT '配置信息',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (type),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='数据采集会话表';

-- 2. 数据包表
CREATE TABLE IF NOT EXISTS packets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT UNSIGNED NOT NULL COMMENT '会话ID',
    timestamp DATETIME NOT NULL COMMENT '时间戳',
    protocol VARCHAR(50) COMMENT '协议类型',
    src_addr VARCHAR(100) COMMENT '源地址',
    dst_addr VARCHAR(100) COMMENT '目标地址',
    src_port INT COMMENT '源端口',
    dst_port INT COMMENT '目标端口',
    length INT NOT NULL COMMENT '数据包长度',
    payload BLOB COMMENT '数据内容',
    analysis_result JSON COMMENT '分析结果',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_session_id (session_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_protocol (protocol),
    INDEX idx_src_addr (src_addr),
    INDEX idx_dst_addr (dst_addr),
    FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='数据包表';

-- 3. 漏洞信息表
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(255) NOT NULL COMMENT '目标地址',
    vuln_type VARCHAR(100) NOT NULL COMMENT '漏洞类型',
    severity VARCHAR(50) NOT NULL COMMENT '严重程度: critical, high, medium, low, info',
    cve_id VARCHAR(50) COMMENT 'CVE编号',
    title VARCHAR(500) COMMENT '漏洞标题',
    description TEXT COMMENT '漏洞描述',
    solution TEXT COMMENT '解决方案',
    references JSON COMMENT '参考链接',
    discovered_at DATETIME NOT NULL COMMENT '发现时间',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_target (target),
    INDEX idx_severity (severity),
    INDEX idx_cve_id (cve_id),
    INDEX idx_discovered_at (discovered_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='漏洞信息表';

-- 4. 扫描任务表
CREATE TABLE IF NOT EXISTS scan_tasks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL COMMENT '任务名称',
    target VARCHAR(500) NOT NULL COMMENT '扫描目标',
    scan_type VARCHAR(50) NOT NULL COMMENT '扫描类型: port, vuln, service',
    status VARCHAR(50) NOT NULL COMMENT '状态: pending, running, completed, failed',
    progress INT DEFAULT 0 COMMENT '进度 0-100',
    result JSON COMMENT '扫描结果',
    error TEXT COMMENT '错误信息',
    start_time DATETIME COMMENT '开始时间',
    end_time DATETIME COMMENT '结束时间',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_scan_type (scan_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='扫描任务表';

-- 5. 攻击操作日志表
CREATE TABLE IF NOT EXISTS attack_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL COMMENT '攻击类型',
    target VARCHAR(500) NOT NULL COMMENT '目标',
    method VARCHAR(100) COMMENT '攻击方法',
    parameters JSON COMMENT '参数',
    result TEXT COMMENT '结果',
    status VARCHAR(50) NOT NULL COMMENT '状态: success, failed',
    user_id VARCHAR(100) COMMENT '用户ID',
    authorized BOOLEAN NOT NULL DEFAULT FALSE COMMENT '是否已授权',
    executed_at DATETIME NOT NULL COMMENT '执行时间',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_attack_type (attack_type),
    INDEX idx_user_id (user_id),
    INDEX idx_executed_at (executed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='攻击操作日志表';

-- 6. 协议统计表
CREATE TABLE IF NOT EXISTS protocol_stats (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT UNSIGNED NOT NULL COMMENT '会话ID',
    protocol VARCHAR(50) NOT NULL COMMENT '协议类型',
    packet_count BIGINT DEFAULT 0 COMMENT '数据包数量',
    byte_count BIGINT DEFAULT 0 COMMENT '字节数',
    first_seen DATETIME NOT NULL COMMENT '首次出现',
    last_seen DATETIME NOT NULL COMMENT '最后出现',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_session_id (session_id),
    INDEX idx_protocol (protocol),
    FOREIGN KEY (session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='协议统计表';

-- 插入示例数据（可选）
-- INSERT INTO capture_sessions (name, type, status, start_time)
-- VALUES ('示例会话', 'ip', 'completed', NOW());

-- 查看表结构
SHOW TABLES;
