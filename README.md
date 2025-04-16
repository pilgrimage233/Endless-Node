# Endless Node

Endless Node 是一个 Minecraft 服务器管理系统的节点端（被控端）。它提供了文件操作、服务器实例管理、认证等功能，可以与主控端配合使用，实现远程管理
Minecraft 服务器。

## 功能特性

- **认证与注册**：主控端可以通过 IP+端口+密钥与节点绑定
- **文件操作**：支持上传、下载、删除、列表等文件操作，主控端可以指定任意路径
- **服务器实例管理**：主控端可以远程创建、启动、停止、删除服务器实例
- **自定义启动脚本**：主控端可以指定自定义的启动和停止脚本
- **控制台访问**：可以查看服务器控制台输出
- **命令执行**：可以向服务器发送命令
- **自动生成访问令牌**：程序第一次启动时自动生成访问令牌
- **全局Token验证**：除了注册接口外，所有接口都需要在请求头中携带有效的token

## 技术栈

- Spring Boot 3.4.4
- MyBatis-Plus 3.5.7
- SQLite 数据库
- WebSocket 支持

## 快速开始

### 环境要求

- JDK 17 或更高版本
- Maven 3.6 或更高版本

### 构建与运行

1. 克隆仓库

```bash
git clone https://github.com/yourusername/Endless-Node.git
cd Endless-Node
```

2. 构建项目

```bash
mvn clean package
```

3. 运行项目

```bash
java -jar target/Endless-Node-0.0.1-SNAPSHOT.jar
```

### 配置

配置文件位于 `src/main/resources/application.yml`，可以根据需要修改以下配置：

```yaml
server:
  port: 8080  # 服务端口

endless:
  node:
    max-instances: 20  # 最大允许的服务器实例数
    default-memory-mb: 1024  # 默认分配给每个服务器的内存（MB）
    default-jvm-args: -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200  # 默认JVM参数
```

## API 文档

### 认证 API

#### 注册主控端

```
POST /api/auth/register
```

请求体：

```json
{
  "ipAddress": "192.168.1.100",
  "port": "8080",
  "secretKey": "your_secret_key"
}
```

响应：

```json
{
  "success": true,
  "message": "Node registered successfully",
  "nodeId": 1,
  "token": "your_access_token",
  "expiresAt": "2023-12-31T23:59:59"
}
```

#### 验证令牌

```
GET /api/auth/verify
```

请求头：

```
X-Endless-Token: your_access_token
```

响应：

```json
{
  "valid": true,
  "masterId": 1,
  "scope": "SERVER_CONTROL,FILE_MANAGE",
  "expiresAt": "2023-12-31T23:59:59"
}
```

### 文件操作 API

#### 获取文件列表

```
GET /api/files/list?path=path/to/directory
```

请求头：

```
X-Endless-Token: your_access_token
```

响应：

```json
{
  "path": "path/to/directory",
  "files": [
    {
      "name": "file1.txt",
      "path": "file1.txt",
      "isDirectory": false,
      "size": 1024,
      "lastModified": 1621234567890
    },
    {
      "name": "directory1",
      "path": "directory1",
      "isDirectory": true,
      "size": 0,
      "lastModified": 1621234567890
    }
  ]
}
```

#### 下载文件

```
GET /api/files/download?path=path/to/file
```

请求头：

```
X-Endless-Token: your_access_token
```

#### 上传文件

```
POST /api/files/upload?path=path/to/directory
```

请求头：

```
X-Endless-Token: your_access_token
```

请求体：multipart/form-data 格式，包含文件

响应：

```json
{
  "success": true,
  "path": "path/to/directory/file.txt",
  "size": 1024
}
```

#### 删除文件或目录

```
DELETE /api/files/delete?path=path/to/file_or_directory
```

请求头：

```
X-Endless-Token: your_access_token
```

响应：

```json
{
  "success": true,
  "path": "path/to/file_or_directory"
}
```

### 服务器实例 API

#### 获取服务器实例列表

```
GET /api/servers/list
```

请求头：

```
X-Endless-Token: your_access_token
```

响应：

```json
{
  "servers": [
    {
      "id": 1,
      "instanceName": "生存主世界",
      "version": "1.20.1",
      "coreType": "PAPER",
      "filePath": "/data/mc_servers/survival",
      "status": "STOPPED",
      "port": 25565,
      "jvmArgs": "-Xmx2G -Xms1G",
      "memoryMb": 2048,
      "createdBy": 1,
      "createdAt": "2023-01-01T00:00:00",
      "updatedAt": null
    }
  ]
}
```

#### 创建服务器实例

```
POST /api/servers/create
```

请求头：

```
X-Endless-Token: your_access_token
```

请求体：

```json
{
  "instanceName": "生存主世界",
  "version": "1.20.1",
  "coreType": "PAPER",
  "filePath": "/data/mc_servers/survival",
  "port": 25565,
  "jvmArgs": "-Xmx2G -Xms1G",
  "memoryMb": 2048
}
```

响应：

```json
{
  "success": true,
  "serverId": 1
}
```

#### 启动服务器实例

```
POST /api/servers/{serverId}/start
```

请求头：

```
X-Endless-Token: your_access_token
```

可选请求体（自定义启动脚本）：

```json
{
  "script": "#!/bin/bash\ncd /data/mc_servers/survival\njava -Xmx2G -Xms1G -jar paper-1.20.1.jar nogui"
}
```

响应：

```json
{
  "success": true,
  "message": "Server started successfully"
}
```

#### 停止服务器实例

```
POST /api/servers/{serverId}/stop
```

请求头：

```
X-Endless-Token: your_access_token
```

可选请求体（自定义停止脚本）：

```json
{
  "script": "#!/bin/bash\ncd /data/mc_servers/survival\nscreen -S mc_server -X stuff \"stop\\n\""
}
```

响应：

```json
{
  "success": true,
  "message": "Server stopped successfully"
}
```

#### 删除服务器实例

```
DELETE /api/servers/{serverId}
```

请求头：

```
X-Endless-Token: your_access_token
```

响应：

```json
{
  "success": true,
  "message": "Server deleted successfully"
}
```

#### 获取服务器控制台输出

```
GET /api/servers/{serverId}/console
```

请求头：

```
X-Endless-Token: your_access_token
```

响应：

```json
{
  "console": "Server console output..."
}
```

#### 向服务器发送命令

```
POST /api/servers/{serverId}/command
```

请求头：

```
X-Endless-Token: your_access_token
```

请求体：

```json
{
  "command": "say Hello, World!"
}
```

响应：

```json
{
  "success": true,
  "message": "Command sent successfully"
}
```

## 许可证

GNU General Public License v3.0

## 作者

- Pilgrimage233 (admin@mcpeach.cc)
