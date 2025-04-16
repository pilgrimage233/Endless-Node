-- 主控端注册表
CREATE TABLE IF NOT EXISTS master_nodes
(
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid               TEXT NOT NULL UNIQUE, -- 主控端唯一标识
    version            TEXT NOT NULL,        -- 主控端软件版本 (如 "v2.1.0")
    secret_key         TEXT NOT NULL,        -- 节点端生成的永久token
    ip_address         TEXT,                 -- 主控端IP地址
    registered_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_communication DATETIME,             -- 最后心跳时间
    is_deleted         INTEGER  DEFAULT 0,   -- 是否删除 (0:正常, 1:已删除)
    protocol_version   TEXT NOT NULL         -- 通信协议版本 (如 "1.0")
);

CREATE INDEX IF NOT EXISTS idx_master_status ON master_nodes (is_deleted, last_communication);

-- 操作日志表
CREATE TABLE IF NOT EXISTS operation_logs
(
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    master_id          INTEGER NOT NULL,   -- 关联 master_nodes.id
    operation_type     TEXT    NOT NULL,   -- 操作类型 (START_SERVER/STOP_SERVER/UPLOAD_FILE)
    operation_time     DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_success         INTEGER  DEFAULT 0, -- 0:失败 1:成功
    detail             TEXT,               -- 操作详情 (JSON格式)
    target_instance_id INTEGER,            -- 关联 server_instances.id
    client_ip          TEXT,               -- 请求来源IP
    user_agent         TEXT,               -- 客户端标识

    FOREIGN KEY (master_id) REFERENCES master_nodes (id)
);

CREATE INDEX IF NOT EXISTS idx_operation_logs ON operation_logs (master_id, operation_time);

-- 服务端实例表
CREATE TABLE IF NOT EXISTS server_instances
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_name TEXT    NOT NULL UNIQUE,    -- 实例名称 (如 "生存主世界")
    version       TEXT    NOT NULL,           -- MC版本 (如 "1.20.1")
    core_type     TEXT    NOT NULL,           -- 服务端核心 (VANILLA/PAPER/SPIGOT)
    file_path     TEXT    NOT NULL,           -- 绝对路径 (如 "/opt/mc/survival")
    status        TEXT     DEFAULT 'STOPPED', -- RUNNING/STOPPED/ERROR
    port          INTEGER  DEFAULT 25565,     -- 服务端口
    jvm_args      TEXT,                       -- JVM启动参数
    memory_mb     INTEGER  DEFAULT 1024,      -- 分配内存 (MB)
    created_by    INTEGER NOT NULL,           -- 关联 master_nodes.id
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME,

    FOREIGN KEY (created_by) REFERENCES master_nodes (id)
);

CREATE INDEX IF NOT EXISTS idx_instance_status ON server_instances (status, core_type);

-- 访问令牌表
CREATE TABLE IF NOT EXISTS access_tokens
(
    token      TEXT PRIMARY KEY,  -- JWT令牌
    master_id  INTEGER  NOT NULL, -- 关联 master_nodes.id
    expires_at DATETIME NOT NULL, -- 过期时间
    scope      TEXT     NOT NULL, -- 权限范围 (SERVER_CONTROL/FILE_MANAGE)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (master_id) REFERENCES master_nodes (id)
);

-- 节点元数据表
CREATE TABLE IF NOT EXISTS node_metadata
(
    key         TEXT PRIMARY KEY, -- 配置键
    value       TEXT NOT NULL,    -- 配置值 (JSON格式)
    description TEXT              -- 配置说明
);

-- 初始数据示例
INSERT OR IGNORE INTO node_metadata (key, value, description)
VALUES ('storage_root', '"/data/mc_servers"', '服务端存储根目录'),
       ('max_instances', '20', '最大允许实例数'),
       ('network_interface', '"eth0"', '绑定网络接口');