package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.common.constant.OperationType;
import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.OperationLogs;
import cc.endmc.endlessnode.domain.ServerInstances;
import cc.endmc.endlessnode.manage.AsyncManager;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.service.OperationLogsService;
import cc.endmc.endlessnode.service.ServerInstancesService;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * 服务器实例控制器
 * 处理服务器实例的启动、停止、重启等操作
 */
@Slf4j
@RestController
@RequestMapping("/api/servers")
@RequiredArgsConstructor
public class ServerController {

    private final AccessTokensService accessTokensService;
    private final ServerInstancesService serverInstancesService;
    private final OperationLogsService operationLogsService;
    private final SimpMessagingTemplate messagingTemplate;

    private static final String TOPIC_CONSOLE = "/topic/console/";
    private static final int MAX_INSTANCES_PER_USER = 20;
    private static final int DEFAULT_MEMORY_MB = 1024;
    private static final String DEFAULT_JVM_ARGS = "-XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200";
    private static final long RESTART_WAIT_TIME_MS = 5000;
    private static final long FORCE_KILL_TIMEOUT_SECONDS = 10;

    // 用于同步服务器操作的锁对象
    private static final Map<Integer, Object> SERVER_LOCKS = new HashMap<>();

    /**
     * 获取服务器操作锁
     */
    private Object getServerLock(Integer serverId) {
        synchronized (SERVER_LOCKS) {
            return SERVER_LOCKS.computeIfAbsent(serverId, k -> new Object());
        }
    }

    /**
     * 应用关闭时的清理方法
     * 确保所有运行中的服务器进程被正确关闭
     */
    @PreDestroy
    public void cleanup() {
        log.info("应用正在关闭，开始清理运行中的服务器进程...");

        // 获取所有运行中的服务器ID
        Set<Integer> runningServerIds = new HashSet<>(Node.getRunningServers().keySet());

        if (runningServerIds.isEmpty()) {
            log.info("没有运行中的服务器进程需要清理");
            return;
        }

        log.info("发现 {} 个运行中的服务器，准备停止", runningServerIds.size());

        // 遍历所有运行中的服务器并尝试优雅关闭
        for (Integer serverId : runningServerIds) {
            try {
                Process process = Node.getRunningServers().get(serverId);
                if (process == null || !process.isAlive()) {
                    Node.getRunningServers().remove(serverId);
                    continue;
                }

                log.info("正在停止服务器: {}", serverId);

                // 停止控制台输出线程
                stopConsoleOutputThread(serverId);

                // 尝试向Minecraft服务器发送stop命令
                try {
                    OutputStreamWriter writer = Node.getServerWriters().get(serverId);
                    if (writer == null) {
                        OutputStream outputStream = process.getOutputStream();
                        if (outputStream != null) {
                            writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
                        }
                    }

                    if (writer != null) {
                        writer.write("stop\n");
                        writer.flush();
                        log.debug("已向服务器 {} 发送stop命令", serverId);
                    }
                } catch (Exception e) {
                    log.warn("向服务器 {} 发送stop命令失败: {}", serverId, e.getMessage());
                }

                // 等待进程优雅终止（最多等待10秒）
                boolean terminated = process.waitFor(10, TimeUnit.SECONDS);

                if (!terminated) {
                    log.warn("服务器 {} 未能在10秒内优雅终止，强制终止", serverId);
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }

                // 清理资源
                Node.getRunningServers().remove(serverId);
                OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                closeWriter(writer);

                // 更新数据库中的服务器状态
                try {
                    ServerInstances server = serverInstancesService.getById(serverId);
                    if (server != null) {
                        server.setStatus("STOPPED");
                        server.setUpdatedAt(new Date());
                        serverInstancesService.updateById(server);
                    }
                } catch (Exception e) {
                    log.error("更新服务器 {} 状态失败", serverId, e);
                }

                log.info("服务器 {} 已成功停止", serverId);

            } catch (Exception e) {
                log.error("停止服务器 {} 时发生错误", serverId, e);

                // 强制清理资源
                try {
                    Process process = Node.getRunningServers().remove(serverId);
                    if (process != null && process.isAlive()) {
                        process.destroyForcibly();
                    }
                    OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                    closeWriter(writer);
                } catch (Exception cleanupEx) {
                    log.error("强制清理服务器 {} 资源时发生错误", serverId, cleanupEx);
                }
            }
        }

        // 清理所有控制台线程
        Set<Integer> consoleThreadIds = new HashSet<>(Node.getConsoleThreads().keySet());
        for (Integer serverId : consoleThreadIds) {
            stopConsoleOutputThread(serverId);
        }

        log.info("所有服务器进程清理完成");
    }

    /**
     * 验证访问令牌并返回令牌信息
     *
     * @param token 访问令牌
     * @return 令牌信息，如果无效则返回 null
     */
    private AccessTokens validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            log.warn("令牌为空");
            return null;
        }

        try {
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            if (accessToken == null) {
                log.warn("无效的令牌: {}", token);
            }

            return accessToken;
        } catch (Exception e) {
            log.error("验证令牌时发生错误", e);
            return null;
        }
    }

    /**
     * 验证用户对服务器实例的访问权限
     *
     * @param server      服务器实例
     * @param accessToken 访问令牌
     * @return 如果有权限返回 true，否则返回 false
     */
    private boolean hasServerPermission(ServerInstances server, AccessTokens accessToken) {
        if (server == null || accessToken == null) {
            return false;
        }

        return server.getCreatedBy() != null &&
                server.getCreatedBy().equals(accessToken.getMasterUuid());
    }

    /**
     * 安全地关闭 Writer
     */
    private void closeWriter(Writer writer) {
        if (writer != null) {
            try {
                writer.close();
            } catch (IOException e) {
                log.error("关闭Writer时发生错误", e);
            }
        }
    }

    /**
     * 安全地关闭 Reader
     */
    private void closeReader(Reader reader) {
        if (reader != null) {
            try {
                reader.close();
            } catch (IOException e) {
                log.error("关闭Reader时发生错误", e);
            }
        }
    }

    /**
     * 获取服务器实例列表
     *
     * @param token 访问令牌
     * @return 服务器实例列表
     */
    @GetMapping("/list")
    public ResponseEntity<Map<String, Object>> listServers(@RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token) {
        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        try {
            // 获取服务器实例列表
            List<ServerInstances> instances = serverInstancesService.lambdaQuery()
                    .eq(ServerInstances::getCreatedBy, accessToken.getMasterUuid())
                    .list();

            // 更新实例状态
            for (ServerInstances instance : instances) {
                if (instance != null && instance.getId() != null) {
                    boolean isRunning = Node.getRunningServers().containsKey(instance.getId());
                    String currentStatus = instance.getStatus();
                    boolean statusNeedsUpdate = isRunning != "RUNNING".equals(currentStatus);

                    if (statusNeedsUpdate) {
                        instance.setStatus(isRunning ? "RUNNING" : "STOPPED");
                        serverInstancesService.updateById(instance);
                    }
                }
            }

            Map<String, Object> response = new HashMap<>();
            response.put("servers", instances);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("获取用户服务器列表时发生错误: {}", accessToken.getMasterUuid(), e);
            return ResponseEntity.status(500).body(Map.of("error", "获取服务器列表失败"));
        }
    }

    /**
     * 创建服务器实例
     *
     * @param token  访问令牌
     * @param server 服务器实例信息
     * @return 创建结果
     */
    @PostMapping("/create")
    public ResponseEntity<Map<String, Object>> createServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @RequestBody ServerInstances server) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证输入参数
        if (server == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器实例信息不能为空"));
        }

        if (server.getInstanceName() == null || server.getInstanceName().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器实例名称不能为空"));
        }

        if (server.getFilePath() == null || server.getFilePath().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器文件路径不能为空"));
        }

        try {
            // 检查实例数量限制
            long instanceCount = serverInstancesService.lambdaQuery()
                    .eq(ServerInstances::getCreatedBy, accessToken.getMasterUuid())
                    .count();

            if (instanceCount >= MAX_INSTANCES_PER_USER) {
                return ResponseEntity.badRequest().body(Map.of("error", "已达到最大实例数量限制"));
            }

            // 设置默认值
            if (server.getMemoryMb() == null || server.getMemoryMb() <= 0) {
                server.setMemoryMb(DEFAULT_MEMORY_MB);
            }

            if (server.getJvmArgs() == null || server.getJvmArgs().trim().isEmpty()) {
                server.setJvmArgs(DEFAULT_JVM_ARGS);
            }

            // 设置创建者
            server.setCreatedBy(accessToken.getMasterUuid());
            server.setCreatedAt(new Date());
            server.setStatus("STOPPED");

            // 保存服务器实例
            serverInstancesService.save(server);

            // 记录操作日志
            logOperation(accessToken.getMasterId(), OperationType.CREATE_SERVER, true,
                    Map.of("instanceId", server.getId(), "instanceName", server.getInstanceName()));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("serverId", server.getId());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("为用户创建服务器时发生错误: {}", accessToken.getMasterUuid(), e);
            logOperation(accessToken.getMasterId(), OperationType.CREATE_SERVER, false,
                    Map.of("error", e.getMessage()));
            return ResponseEntity.status(500).body(Map.of("error", "创建服务器失败: " + e.getMessage()));
        }
    }

    /**
     * 启动服务器实例
     *
     * @param token       访问令牌
     * @param serverId    服务器实例ID
     * @param startScript 可选的启动脚本
     * @return 启动结果
     */
    @PostMapping("/{serverId}/start")
    public ResponseEntity<Map<String, Object>> startServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> startScript) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 使用锁防止并发启动同一服务器
        synchronized (getServerLock(serverId)) {
            // 检查服务器是否已运行
            if (Node.getRunningServers().containsKey(serverId)) {
                return ResponseEntity.badRequest().body(Map.of("error", "服务器已经在运行中"));
            }

            Process process = null;
            try {
                // 启动服务器
                if (startScript != null && startScript.containsKey("script") &&
                        startScript.get("script") != null && !startScript.get("script").trim().isEmpty()) {
                    // 使用主控端提供的启动脚本
                    process = startMinecraftServerWithScript(server, startScript.get("script"));
                } else {
                    // 使用默认启动方式
                    process = startMinecraftServer(server);
                }

                // 验证进程是否成功启动
                if (process == null || !process.isAlive()) {
                    throw new IOException("进程启动失败");
                }

                Node.getRunningServers().put(serverId, process);

                // 启动控制台输出线程
                startConsoleOutputThread(serverId, process);

                // 更新服务器状态
                server.setStatus("RUNNING");
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.START_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "服务器启动成功");

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                log.error("启动服务器时发生错误: {}", serverId, e);

                // 清理失败的启动
                if (process != null) {
                    try {
                        process.destroyForcibly();
                    } catch (Exception cleanupEx) {
                        log.error("清理失败的进程时发生错误", cleanupEx);
                    }
                }
                Node.getRunningServers().remove(serverId);
                stopConsoleOutputThread(serverId);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.START_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "启动服务器失败: " + e.getMessage()));
            }
        }
    }

    /**
     * 停止服务器实例
     *
     * @param token      访问令牌
     * @param serverId   服务器实例ID
     * @param stopScript 可选的停止脚本
     * @return 停止结果
     */
    @PostMapping("/{serverId}/stop")
    public ResponseEntity<Map<String, Object>> stopServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> stopScript) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 使用锁防止并发操作同一服务器
        synchronized (getServerLock(serverId)) {
            // 检查服务器是否已停止
            Process process = Node.getRunningServers().get(serverId);
            if (process == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
            }

            try {
                // 停止控制台输出线程
                stopConsoleOutputThread(serverId);

                // 停止服务器
                if (stopScript != null && stopScript.containsKey("script") &&
                        stopScript.get("script") != null && !stopScript.get("script").trim().isEmpty()) {
                    // 使用主控端提供的停止脚本
                    executeStopScript(server, stopScript.get("script"));
                } else {
                    // 使用默认停止方式
                    process.destroy();
                }

                // 等待进程终止（最多等待5秒）
                boolean terminated = process.waitFor(5, TimeUnit.SECONDS);
                if (!terminated) {
                    log.warn("服务器 {} 未能正常终止，强制终止中", serverId);
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }

                // 清理资源
                Node.getRunningServers().remove(serverId);
                OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                closeWriter(writer);

                // 更新服务器状态
                server.setStatus("STOPPED");
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.STOP_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "服务器停止成功");

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                log.error("停止服务器时发生错误: {}", serverId, e);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.STOP_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "停止服务器失败: " + e.getMessage()));
            }
        }
    }

    /**
     * 重启服务器实例
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @param scripts  可选的启动和停止脚本
     * @return 重启结果
     */
    @PostMapping("/{serverId}/restart")
    public ResponseEntity<Map<String, Object>> restartServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> scripts) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 使用锁防止并发操作同一服务器
        synchronized (getServerLock(serverId)) {
            // 检查服务器是否在运行
            Process process = Node.getRunningServers().get(serverId);
            if (process == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
            }

            Process newProcess = null;
            try {
                // 停止控制台输出线程
                stopConsoleOutputThread(serverId);

                // 停止服务器
                if (scripts != null && scripts.containsKey("stopScript") &&
                        scripts.get("stopScript") != null && !scripts.get("stopScript").trim().isEmpty()) {
                    // 使用主控端提供的停止脚本
                    executeStopScript(server, scripts.get("stopScript"));
                } else {
                    // 使用默认停止方式
                    process.destroy();
                }

                // 等待进程终止（最多等待5秒）
                boolean terminated = process.waitFor(5, TimeUnit.SECONDS);
                if (!terminated) {
                    log.warn("重启时服务器 {} 未能正常终止，强制终止中", serverId);
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }

                // 清理资源
                Node.getRunningServers().remove(serverId);
                OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                closeWriter(writer);

                // 等待进程完全终止
                try {
                    Thread.sleep(RESTART_WAIT_TIME_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    log.warn("服务器重启等待被中断: {}", serverId);
                }

                // 启动服务器
                if (scripts != null && scripts.containsKey("startScript") &&
                        scripts.get("startScript") != null && !scripts.get("startScript").trim().isEmpty()) {
                    // 使用主控端提供的启动脚本
                    newProcess = startMinecraftServerWithScript(server, scripts.get("startScript"));
                } else {
                    // 使用默认启动方式
                    newProcess = startMinecraftServer(server);
                }

                // 验证进程是否成功启动
                if (newProcess == null || !newProcess.isAlive()) {
                    throw new IOException("重启后进程启动失败");
                }

                Node.getRunningServers().put(serverId, newProcess);

                // 启动控制台输出线程
                startConsoleOutputThread(serverId, newProcess);

                // 更新服务器状态
                server.setStatus("RUNNING");
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.RESTART_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "服务器重启成功");

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                log.error("重启服务器时发生错误: {}", serverId, e);

                // 清理失败的重启
                if (newProcess != null) {
                    try {
                        newProcess.destroyForcibly();
                    } catch (Exception cleanupEx) {
                        log.error("清理失败的重启进程时发生错误", cleanupEx);
                    }
                }
                Node.getRunningServers().remove(serverId);
                stopConsoleOutputThread(serverId);

                // 更新服务器状态为已停止
                try {
                    server.setStatus("STOPPED");
                    server.setUpdatedAt(new Date());
                    serverInstancesService.updateById(server);
                } catch (Exception updateEx) {
                    log.error("重启失败后更新服务器状态时发生错误", updateEx);
                }

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.RESTART_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "重启服务器失败: " + e.getMessage()));
            }
        }
    }

    /**
     * 强制终止服务器实例
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 终止结果
     */
    @PostMapping("/{serverId}/kill")
    public ResponseEntity<Map<String, Object>> killServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 使用锁防止并发操作同一服务器
        synchronized (getServerLock(serverId)) {
            // 检查服务器是否在运行
            Process process = Node.getRunningServers().get(serverId);
            if (process == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
            }

            try {
                // 停止控制台输出线程
                stopConsoleOutputThread(serverId);

                // 强制终止进程
                process.destroyForcibly();

                // 等待进程完全终止
                boolean terminated = process.waitFor(FORCE_KILL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                if (!terminated) {
                    // 如果进程仍然存在，记录警告
                    log.warn("服务器 {} 的进程在 {} 秒内未终止",
                            serverId, FORCE_KILL_TIMEOUT_SECONDS);
                    logOperation(accessToken.getMasterId(), OperationType.KILL_SERVER, false,
                            Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                    "warning", "进程在" + FORCE_KILL_TIMEOUT_SECONDS + "秒内未终止"));
                }

                // 清理资源
                Node.getRunningServers().remove(serverId);
                OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                closeWriter(writer);

                // 更新服务器状态
                server.setStatus("STOPPED");
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.KILL_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "服务器强制终止成功");

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                log.error("强制终止服务器时发生错误: {}", serverId, e);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.KILL_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "强制终止服务器失败: " + e.getMessage()));
            }
        }
    }

    /**
     * 删除服务器实例
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 删除结果
     */
    @DeleteMapping("/{serverId}")
    public ResponseEntity<Map<String, Object>> deleteServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 使用锁防止并发操作同一服务器
        synchronized (getServerLock(serverId)) {
            // 检查服务器是否正在运行
            if (Node.getRunningServers().containsKey(serverId)) {
                return ResponseEntity.badRequest().body(Map.of("error", "无法删除正在运行的服务器"));
            }

            try {
                // 删除服务器实例
                serverInstancesService.removeById(serverId);

                // 清理锁对象
                synchronized (SERVER_LOCKS) {
                    SERVER_LOCKS.remove(serverId);
                }

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.DELETE_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "服务器删除成功");

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                log.error("删除服务器时发生错误: {}", serverId, e);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.DELETE_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "删除服务器失败: " + e.getMessage()));
            }
        }
    }

    /**
     * 获取服务器控制台输出
     * 注意：此方法会阻塞直到读取完所有可用输出，建议使用 WebSocket 订阅实时输出
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 控制台输出
     */
    @GetMapping("/{serverId}/console")
    public ResponseEntity<Map<String, Object>> getConsole(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否正在运行
        Process process = Node.getRunningServers().get(serverId);
        if (process == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        BufferedReader reader = null;
        try {
            // 读取控制台输出（注意：这可能会阻塞，建议使用 WebSocket）
            InputStream inputStream = process.getInputStream();
            if (inputStream == null) {
                return ResponseEntity.status(500).body(Map.of("error", "无法获取控制台输出流"));
            }

            reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            StringBuilder output = new StringBuilder();
            String line;

            // 只读取当前可用的输出，避免阻塞
            while (reader.ready() && (line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            Map<String, Object> response = new HashMap<>();
            response.put("console", output.toString());
            response.put("message", "建议使用 WebSocket 订阅实时控制台输出");

            return ResponseEntity.ok(response);
        } catch (IOException e) {
            log.error("读取服务器控制台输出时发生错误: {}", serverId, e);
            return ResponseEntity.status(500).body(Map.of("error", "读取控制台失败: " + e.getMessage()));
        } finally {
            // 注意：不要关闭 reader，因为进程还在运行
            // 控制台输出线程会持续读取
        }
    }

    /**
     * 向服务器发送命令
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @param request  请求体，包含命令内容
     * @return 命令执行结果
     */
    @PostMapping("/{serverId}/command")
    public ResponseEntity<Map<String, Object>> sendCommand(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody Map<String, String> request) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 验证请求体
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "请求体不能为空"));
        }

        String command = request.get("command");
        if (command == null || command.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "命令不能为空"));
        }

        // 使用锁防止并发命令发送
        synchronized (getServerLock(serverId)) {
            // 检查服务器是否正在运行
            Process process = Node.getRunningServers().get(serverId);
            if (process == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
            }

            // 检查进程是否存活
            if (!process.isAlive()) {
                Node.getRunningServers().remove(serverId);
                Node.getServerWriters().remove(serverId);
                return ResponseEntity.badRequest().body(Map.of("error", "服务器进程已终止"));
            }

            try {
                OutputStreamWriter writer;
                if (Node.getServerWriters().containsKey(serverId)) {
                    writer = Node.getServerWriters().get(serverId);
                } else {
                    OutputStream outputStream = process.getOutputStream();
                    if (outputStream == null) {
                        return ResponseEntity.status(500).body(Map.of("error", "无法获取进程输出流"));
                    }
                    writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
                    Node.getServerWriters().put(serverId, writer);
                }

                // 向进程输入命令
                writer.write(command + "\n");
                writer.flush();

                log.info("向服务器 {} 发送命令: {}", serverId, command);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.SEND_COMMAND, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "command", command));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "命令发送成功");

                return ResponseEntity.ok(response);

            } catch (Exception e) {
                log.error("向服务器发送命令时发生错误: {}, 命令: {}", serverId, command, e);

                logOperation(accessToken.getMasterId(), OperationType.SEND_COMMAND, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "command", command, "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "发送命令失败: " + e.getMessage()));
            }
        }
    }


    /**
     * WebSocket消息处理 - 订阅服务器控制台
     *
     * @param request 请求参数
     */
    @MessageMapping("/console/subscribe")
    public void subscribeConsole(@Payload Map<String, Object> request) {
        if (request == null) {
            log.warn("收到空的订阅请求");
            return;
        }

        Integer serverId = null;
        String token = null;

        try {
            serverId = (Integer) request.get("serverId");
            token = (String) request.get("token");
        } catch (ClassCastException e) {
            log.error("请求参数无效", e);
            return;
        }

        if (serverId == null || serverId <= 0) {
            log.warn("订阅请求中的服务器ID无效: {}", serverId);
            return;
        }

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId,
                    Map.of("error", "无效的访问令牌"));
            return;
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId,
                    Map.of("error", "未找到服务器"));
            return;
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId,
                    Map.of("error", "权限不足"));
            return;
        }

        // 检查服务器是否正在运行
        Process process = Node.getRunningServers().get(serverId);
        if (process == null || !process.isAlive()) {
            messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId,
                    Map.of("error", "服务器未在运行"));
            return;
        }

        // 发送订阅成功消息
        messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId,
                Map.of("message", "已订阅控制台输出"));
    }

    /**
     * 启动控制台输出线程
     *
     * @param serverId 服务器ID
     * @param process  进程对象
     */
    private void startConsoleOutputThread(Integer serverId, Process process) {
        if (serverId == null || process == null) {
            log.warn("无法启动控制台输出线程: serverId 或 process 为空");
            return;
        }

        // 如果已经有线程在运行，先停止它
        stopConsoleOutputThread(serverId);

        // 创建新的线程来读取控制台输出
        Thread consoleThread = new Thread(() -> {
            BufferedReader reader = null;
            try {
                InputStream inputStream = process.getInputStream();
                if (inputStream == null) {
                    log.error("无法获取服务器的输入流: {}", serverId);
                    return;
                }

                reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
                String line;
                while (!Thread.currentThread().isInterrupted() && (line = reader.readLine()) != null) {
                    // 发送控制台输出到WebSocket
                    final String finalLine = line;
                    try {
                        messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId,
                                Map.of("line", finalLine));
                    } catch (Exception e) {
                        log.error("向WebSocket发送服务器控制台输出时发生错误: {}", serverId, e);
                        // 继续读取，不要因为发送失败而中断
                    }
                }
            } catch (IOException e) {
                // 如果进程已经终止，这是正常的
                if (!process.isAlive()) {
                    log.debug("服务器控制台输出线程正常终止: {}", serverId);
                    return;
                }

                // 否则，记录错误
                log.error("读取服务器控制台输出时发生错误: {}", serverId, e);
                try {
                    messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId,
                            Map.of("error", "读取控制台失败: " + e.getMessage()));
                } catch (Exception sendEx) {
                    log.error("向WebSocket发送错误消息时发生错误", sendEx);
                }
            } finally {
                // 不要关闭 reader，因为它关联到进程的输入流
                // 进程终止时会自动关闭
                log.debug("服务器控制台输出线程已结束: {}", serverId);
            }
        }, "ConsoleThread-" + serverId);

        // 设置为守护线程，这样当主线程结束时，这个线程也会结束
        consoleThread.setDaemon(true);

        // 启动线程
        consoleThread.start();

        // 保存线程引用
        Node.getConsoleThreads().put(serverId, consoleThread);

        log.debug("已启动服务器控制台输出线程: {}", serverId);
    }

    /**
     * 停止控制台输出线程
     *
     * @param serverId 服务器ID
     */
    private void stopConsoleOutputThread(Integer serverId) {
        if (serverId == null) {
            return;
        }

        Thread consoleThread = Node.getConsoleThreads().remove(serverId);
        if (consoleThread != null && consoleThread.isAlive()) {
            try {
                // 中断线程
                consoleThread.interrupt();

                // 等待线程终止（最多等待2秒）
                consoleThread.join(5000);

                if (consoleThread.isAlive()) {
                    log.warn("服务器 {} 的控制台线程在超时时间内未终止", serverId);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("等待控制台线程终止时被中断", e);
            }
        }

        log.debug("已停止服务器控制台输出线程: {}", serverId);
    }

    /**
     * 启动Minecraft服务器
     *
     * @param server 服务器实例
     * @return 进程对象
     * @throws IOException IO异常
     */
    private Process startMinecraftServer(ServerInstances server) throws IOException {
        if (server == null) {
            throw new IllegalArgumentException("Server instance cannot be null");
        }

        if (server.getFilePath() == null || server.getFilePath().trim().isEmpty()) {
            throw new IllegalArgumentException("Server file path cannot be empty");
        }

        // 构建启动命令
        List<String> command = new ArrayList<>();
        command.add("java");

        // 添加JVM参数
        if (server.getJvmArgs() != null && !server.getJvmArgs().trim().isEmpty()) {
            String[] jvmArgs = server.getJvmArgs().trim().split("\\s+");
            command.addAll(Arrays.asList(jvmArgs));
        } else {
            // 默认JVM参数
            Integer memory = server.getMemoryMb();
            if (memory == null || memory <= 0) {
                memory = DEFAULT_MEMORY_MB;
            }
            command.add("-Xmx" + memory + "M");
            command.add("-Xms" + (memory / 2) + "M");
        }

        // 添加jar文件路径
        String jarFileName = getJarFileName(server);
        String jarPath = server.getFilePath() + File.separator + jarFileName;
        command.add("-jar");
        command.add(jarPath);

        // 添加服务器参数
        command.add("nogui");

        // 创建工作目录
        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            boolean created = workingDir.mkdirs();
            if (!created) {
                throw new IOException("Failed to create working directory: " + workingDir.getAbsolutePath());
            }
        }

        // 验证工作目录
        if (!workingDir.isDirectory()) {
            throw new IOException("Working directory path is not a directory: " + workingDir.getAbsolutePath());
        }

        // 验证jar文件是否存在
        File jarFile = new File(jarPath);
        if (!jarFile.exists()) {
            log.warn("JAR文件不存在: {}", jarPath);
            // 不抛出异常，让进程尝试启动，可能会报错
        }

        // 启动进程
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(workingDir);
        processBuilder.redirectErrorStream(true);

        log.info("正在启动服务器 {} ，使用命令: {}", server.getId(), String.join(" ", command));

        return processBuilder.start();
    }

    /**
     * 使用自定义脚本启动Minecraft服务器
     *
     * @param server 服务器实例
     * @param script 启动脚本
     * @return 进程对象
     * @throws IOException IO异常
     */
    private Process startMinecraftServerWithScript(ServerInstances server, String script) throws IOException {
        if (server == null) {
            throw new IllegalArgumentException("Server instance cannot be null");
        }

        if (script == null || script.trim().isEmpty()) {
            throw new IllegalArgumentException("Start script cannot be empty");
        }

        if (server.getFilePath() == null || server.getFilePath().trim().isEmpty()) {
            throw new IllegalArgumentException("Server file path cannot be empty");
        }

        // 创建工作目录
        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            boolean created = workingDir.mkdirs();
            if (!created) {
                throw new IOException("无法创建工作目录: " + workingDir.getAbsolutePath());
            }
        }

        // 验证工作目录
        if (!workingDir.isDirectory()) {
            throw new IOException("工作目录路径不是一个目录: " + workingDir.getAbsolutePath());
        }

        // 拆分命令字符串（比如 "java -Xmx2G -Xms2G -jar server.jar nogui"）
        String trimmedScript = script.trim();
        List<String> commandParts = new ArrayList<>(Arrays.asList(trimmedScript.split("\\s+")));

        // 移除空字符串
        commandParts.removeIf(String::isEmpty);

        if (commandParts.isEmpty()) {
            throw new IllegalArgumentException("Start script contains no valid commands");
        }

        // 获取操作系统类型
        String osName = System.getProperty("os.name");
        if (osName == null) {
            osName = "unknown";
        }

        ProcessBuilder processBuilder;
        if (osName.toLowerCase().contains("windows")) {
            // Windows 系统直接执行命令
            processBuilder = new ProcessBuilder(commandParts);
        } else {
            // Unix/Linux 系统使用 bash
            List<String> unixCommand = new ArrayList<>();
            unixCommand.add("bash");
            unixCommand.add("-c");
            unixCommand.add(trimmedScript);
            processBuilder = new ProcessBuilder(unixCommand);
        }

        processBuilder.directory(workingDir);
        processBuilder.redirectErrorStream(true);

        log.info("正在使用自定义脚本启动服务器 {}: {}", server.getId(), trimmedScript);

        // 启动进程
        return processBuilder.start();
    }


    /**
     * 执行停止脚本
     *
     * @param server 服务器实例
     * @param script 停止脚本
     * @throws IOException IO异常
     */
    private void executeStopScript(ServerInstances server, String script) throws IOException {
        if (server == null) {
            throw new IllegalArgumentException("Server instance cannot be null");
        }

        if (script == null || script.trim().isEmpty()) {
            throw new IllegalArgumentException("Stop script cannot be empty");
        }

        Integer serverId = server.getId();
        if (serverId == null) {
            throw new IllegalArgumentException("Server ID cannot be null");
        }

        // 获取运行中的进程
        final Process process = Node.getRunningServers().get(serverId);
        if (process == null) {
            throw new IOException("服务器未在运行");
        }

        // 检查进程是否存活
        if (!process.isAlive()) {
            throw new IOException("服务器进程已终止");
        }

        OutputStreamWriter writer;
        if (Node.getServerWriters().containsKey(serverId)) {
            writer = Node.getServerWriters().get(serverId);
        } else {
            OutputStream outputStream = process.getOutputStream();
            if (outputStream == null) {
                throw new IOException("无法获取进程输出流");
            }
            writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
            Node.getServerWriters().put(serverId, writer);
        }

        // 执行停止命令
        writer.write(script.trim() + "\n");
        writer.flush();

        log.info("已为服务器 {} 执行停止脚本: {}", serverId, script.trim());
    }

    /**
     * 获取服务器jar文件名
     *
     * @param server 服务器实例
     * @return jar文件名
     */
    private String getJarFileName(ServerInstances server) {
        if (server == null) {
            return "server.jar";
        }

        String coreType = server.getCoreType();
        String version = server.getVersion();

        // 如果核心类型为空，返回默认名称
        if (coreType == null || coreType.trim().isEmpty()) {
            return "server.jar";
        }

        // 根据核心类型和版本获取jar文件名
        // 这里只是一个示例，实际实现可能需要从配置或下载获取
        String normalizedCoreType = coreType.trim().toUpperCase();
        switch (normalizedCoreType) {
            case "VANILLA":
                if (version != null && !version.trim().isEmpty()) {
                    return "minecraft_server." + version.trim() + ".jar";
                }
                return "minecraft_server.jar";
            case "PAPER":
                if (version != null && !version.trim().isEmpty()) {
                    return "paper-" + version.trim() + ".jar";
                }
                return "paper.jar";
            case "SPIGOT":
                if (version != null && !version.trim().isEmpty()) {
                    return "spigot-" + version.trim() + ".jar";
                }
                return "spigot.jar";
            case "FORGE":
                if (version != null && !version.trim().isEmpty()) {
                    return "forge-" + version.trim() + ".jar";
                }
                return "forge.jar";
            case "FABRIC":
                if (version != null && !version.trim().isEmpty()) {
                    return "fabric-server-" + version.trim() + ".jar";
                }
                return "fabric-server.jar";
            default:
                log.warn("未知的核心类型: {}，使用默认 server.jar", coreType);
                return "server.jar";
        }
    }

    /**
     * 记录操作日志
     *
     * @param masterId      主控端ID
     * @param operationType 操作类型
     * @param isSuccess     是否成功
     * @param detail        详细信息
     */
    private void logOperation(Integer masterId, String operationType, boolean isSuccess, Map<String, Object> detail) {
        // 参数验证
        if (masterId == null || operationType == null) {
            log.warn("无法记录操作日志: masterId 或 operationType 为空");
            return;
        }

        try {
            AsyncManager.me().execute(new TimerTask() {
                @Override
                public void run() {
                    try {
                        OperationLogs operationLog = new OperationLogs();
                        operationLog.setMasterId(masterId);
                        operationLog.setOperationType(operationType);
                        operationLog.setOperationTime(new Date());
                        operationLog.setIsSuccess(isSuccess ? 1 : 0);

                        // 安全地转换 detail 为字符串
                        String detailString = (detail != null) ? detail.toString() : "";
                        operationLog.setDetail(detailString);

                        operationLogsService.save(operationLog);

                        log.debug("操作日志已保存: masterId={}, type={}, success={}",
                                masterId, operationType, isSuccess);
                    } catch (Exception e) {
                        log.error("保存操作日志失败: masterId={}, type={}, success={}",
                                masterId, operationType, isSuccess, e);
                    }
                }
            });
        } catch (Exception e) {
            log.error("调度操作日志任务失败", e);
        }
    }
}