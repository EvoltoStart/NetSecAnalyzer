# 数据库脚本说明

## 数据库初始化

### 方式一：自动迁移（推荐）

系统使用 GORM 的 AutoMigrate 功能，在首次启动时会自动创建所有表。

**步骤：**
1. 手动创建数据库：
```sql
CREATE DATABASE netsecanalyzer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

2. 配置 `configs/config.yaml` 中的数据库连接信息

3. 启动程序，表会自动创建：
```bash
go run cmd/server/main.go -config ./configs/config.yaml
```

### 方式二：使用 SQL 脚本

如果不想使用自动迁移，可以手动执行 SQL 脚本：

```bash
# 登录 MySQL
mysql -u root -p

# 执行初始化脚本
source /home/meng/Projects/GolandProjects/NetSecAnalyzer/scripts/init.sql
```

## 表结构说明

### 1. capture_sessions - 数据采集会话表
存储数据采集会话的元信息。

**主要字段：**
- `name`: 会话名称
- `type`: 采集类型（ip/can/rs485）
- `status`: 状态（running/stopped/completed）
- `packet_count`: 采集的数据包数量
- `config`: JSON 格式的配置信息

### 2. packets - 数据包表
存储采集到的所有数据包。

**主要字段：**
- `session_id`: 关联的会话ID
- `timestamp`: 数据包时间戳
- `protocol`: 协议类型
- `src_addr/dst_addr`: 源/目标地址
- `src_port/dst_port`: 源/目标端口
- `payload`: 数据包内容（二进制）
- `analysis_result`: 协议分析结果（JSON）

**注意：** 此表数据量可能很大，建议：
- 定期归档历史数据
- 根据时间分区
- 限制 payload 大小

### 3. vulnerabilities - 漏洞信息表
存储扫描发现的漏洞。

**主要字段：**
- `target`: 漏洞目标
- `vuln_type`: 漏洞类型
- `severity`: 严重程度（critical/high/medium/low/info）
- `cve_id`: CVE 编号
- `description`: 漏洞描述
- `solution`: 修复建议

### 4. scan_tasks - 扫描任务表
存储扫描任务的执行情况。

**主要字段：**
- `name`: 任务名称
- `target`: 扫描目标
- `scan_type`: 扫描类型（port/service/vuln）
- `status`: 任务状态
- `progress`: 进度（0-100）
- `result`: 扫描结果（JSON）

### 5. attack_logs - 攻击操作日志表
记录所有攻击测试操作，用于审计。

**主要字段：**
- `attack_type`: 攻击类型
- `target`: 攻击目标
- `parameters`: 攻击参数（JSON）
- `user_id`: 操作用户
- `authorized`: 是否已授权
- `executed_at`: 执行时间

**重要：** 此表用于安全审计，不应删除或修改。

### 6. protocol_stats - 协议统计表
存储每个会话的协议统计信息。

**主要字段：**
- `session_id`: 会话ID
- `protocol`: 协议类型
- `packet_count`: 数据包数量
- `byte_count`: 总字节数
- `first_seen/last_seen`: 首次/最后出现时间

## 数据库优化建议

### 索引优化
所有常用查询字段都已添加索引，包括：
- `session_id`, `timestamp`, `protocol` 等

### 分区建议
对于大数据量场景，建议对 `packets` 表按时间分区：

```sql
ALTER TABLE packets PARTITION BY RANGE (YEAR(timestamp)) (
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION p2025 VALUES LESS THAN (2026),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);
```

### 定期清理
建议定期清理历史数据：

```sql
-- 删除 30 天前的数据包
DELETE FROM packets WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);

-- 删除已完成的扫描任务（保留最近 100 条）
DELETE FROM scan_tasks
WHERE status = 'completed'
AND id NOT IN (
    SELECT id FROM (
        SELECT id FROM scan_tasks
        WHERE status = 'completed'
        ORDER BY created_at DESC
        LIMIT 100
    ) tmp
);
```

### 备份建议
重要表需要定期备份：

```bash
# 备份整个数据库
mysqldump -u root -p netsecanalyzer > backup_$(date +%Y%m%d).sql

# 仅备份结构
mysqldump -u root -p --no-data netsecanalyzer > schema.sql

# 仅备份重要表
mysqldump -u root -p netsecanalyzer vulnerabilities attack_logs > important_$(date +%Y%m%d).sql
```

## Docker 环境

使用 Docker Compose 时，数据库会自动执行 `init.sql` 脚本：

```yaml
volumes:
  - ./scripts/init.sql:/docker-entrypoint-initdb.d/init.sql
```

首次启动时会自动初始化数据库和表结构。

## 常见问题

**Q: 表已存在的错误？**
A: 使用了 `IF NOT EXISTS`，不会报错。如需重建，先删除数据库。

**Q: GORM 自动迁移和 SQL 脚本冲突？**
A: 两种方式选其一即可。推荐使用 GORM 自动迁移。

**Q: 如何查看当前表结构？**
A:
```sql
USE netsecanalyzer;
SHOW TABLES;
DESC packets;
```

**Q: 数据包表太大怎么办？**
A:
1. 使用分区表
2. 定期归档历史数据
3. 限制 payload 字段大小
4. 只采集关键数据包
