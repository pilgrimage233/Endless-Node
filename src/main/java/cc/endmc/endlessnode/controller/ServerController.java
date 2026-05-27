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
import cc.endmc.endlessnode.util.CommandLineParser;
import cc.endmc.endlessnode.util.CommandRestrictions;
import cc.endmc.endlessnode.util.MinecraftServerQuery;
import cn.hutool.core.net.Ipv4Util;
import jakarta.annotation.PreDestroy;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private static final int MAX_CONSOLE_LOG_LINES = 2000; // 每个服务器最多缓存2000条日志

    // 用于同步服务器操作的锁对象
    private static final Map<Integer, Object> SERVER_LOCKS = new ConcurrentHashMap<>();

    // 控制台日志缓存：服务器ID -> 日志列表
    private static final ConcurrentHashMap<Integer, LinkedBlockingDeque<String>> CONSOLE_LOG_CACHE = new ConcurrentHashMap<>();

    // Query连接缓存：服务器ID -> Query连接信息
    private static final ConcurrentHashMap<Integer, CachedQueryConnection> QUERY_CONNECTION_CACHE = new ConcurrentHashMap<>();
    private static final long QUERY_CONNECTION_TTL_MS = 30000L; // 30秒缓存时间
    private static final int QUERY_PORT_RANGE_START = 25600; // Query端口范围开始
    private static final int QUERY_PORT_RANGE_END = 27000;   // Query端口范围结束

    // 控制台消息派发队列和线程池
    private static final int CONSOLE_DISPATCH_QUEUE_CAPACITY = 2048;
    private static final AtomicInteger CONSOLE_DISPATCH_THREAD_COUNTER = new AtomicInteger(1);
    private static final BlockingQueue<ConsoleDispatchMessage> CONSOLE_DISPATCH_QUEUE =
            new LinkedBlockingQueue<>(CONSOLE_DISPATCH_QUEUE_CAPACITY);
    private static final ExecutorService CONSOLE_DISPATCH_EXECUTOR = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "ConsoleDispatch-" + CONSOLE_DISPATCH_THREAD_COUNTER.getAndIncrement());
        thread.setDaemon(true);
        return thread;
    });
    private static final long PROCESS_INFO_CACHE_TTL_MS = 5000L;
    private static final ConcurrentHashMap<Long, CachedProcessInfo> PROCESS_INFO_CACHE = new ConcurrentHashMap<>();

    @Value("${endless.security.blocked-mc-commands:op,stop}")
    private String blockedMcCommands;

    // 启动控制台消息派发线程和Query连接清理任务
    static {
        CONSOLE_DISPATCH_EXECUTOR.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    ConsoleDispatchMessage message = CONSOLE_DISPATCH_QUEUE.take();
                    message.dispatch();
                } catch (InterruptedException interruptedException) {
                    Thread.currentThread().interrupt();
                } catch (Exception dispatchError) {
                    log.error("控制台消息派发失败", dispatchError);
                }
            }
        });

        // 启动Query连接清理任务
        ScheduledExecutorService queryCleanupExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "QueryConnectionCleanup");
            thread.setDaemon(true);
            return thread;
        });

        queryCleanupExecutor.scheduleWithFixedDelay(() -> {
            try {
                cleanupExpiredQueryConnections();
            } catch (Exception e) {
                log.error("清理过期Query连接时发生错误", e);
            }
        }, 60, 60, TimeUnit.SECONDS); // 每60秒清理一次
    }

    /**
     * 获取服务器操作锁
     */
    private Object getServerLock(Integer serverId) {
        return SERVER_LOCKS.computeIfAbsent(serverId, k -> new Object());
    }

    /**
     * 清理过期的Query连接
     */
    private static void cleanupExpiredQueryConnections() {
        long currentTime = System.currentTimeMillis();
        List<Integer> expiredKeys = new ArrayList<>();

        for (Map.Entry<Integer, CachedQueryConnection> entry : QUERY_CONNECTION_CACHE.entrySet()) {
            CachedQueryConnection cached = entry.getValue();
            if (cached != null && (currentTime - cached.timestamp >= QUERY_CONNECTION_TTL_MS)) {
                expiredKeys.add(entry.getKey());
            }
        }

        if (!expiredKeys.isEmpty()) {
            log.debug("清理 {} 个过期的Query连接", expiredKeys.size());
            for (Integer serverId : expiredKeys) {
                CachedQueryConnection cached = QUERY_CONNECTION_CACHE.remove(serverId);
                if (cached != null && cached.query != null) {
                    try {
                        cached.query.close();
                        log.debug("关闭服务器 {} 的过期Query连接", serverId);
                    } catch (Exception e) {
                        log.debug("关闭过期Query连接时发生错误: {}", e.getMessage());
                    }
                }
            }
        }
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
                Node.getServerStartTimes().remove(serverId);
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
                    Node.getServerStartTimes().remove(serverId);
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

        CONSOLE_DISPATCH_EXECUTOR.shutdownNow();
        CONSOLE_DISPATCH_QUEUE.clear();

        // 清理Query连接缓存
        cleanupQueryConnections();

        PROCESS_INFO_CACHE.clear();
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
                // 如果主控端提供了启动脚本，提取并更新JVM参数
                if (startScript != null && startScript.containsKey("script") &&
                        startScript.get("script") != null && !startScript.get("script").trim().isEmpty()) {
                    updateServerJvmArgsFromScript(server, startScript.get("script"));
                }

                // 确保Query功能已启用
                ensureQueryEnabled(server);

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

                // 记录启动时间
                Node.getServerStartTimes().put(serverId, System.currentTimeMillis());

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
                Node.getServerStartTimes().remove(serverId);
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
                Node.getServerStartTimes().remove(serverId);
                OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                closeWriter(writer);

                // 清理Query连接缓存
                removeCachedQueryConnection(serverId);

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
                Node.getServerStartTimes().remove(serverId);
                OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                closeWriter(writer);

                // 清理Query连接缓存
                removeCachedQueryConnection(serverId);

                // 等待进程完全终止
                try {
                    Thread.sleep(RESTART_WAIT_TIME_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    log.warn("服务器重启等待被中断: {}", serverId);
                }

                // 如果主控端提供了启动脚本，提取并更新JVM参数
                if (scripts != null && scripts.containsKey("startScript") &&
                        scripts.get("startScript") != null && !scripts.get("startScript").trim().isEmpty()) {
                    updateServerJvmArgsFromScript(server, scripts.get("startScript"));
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

                // 记录启动时间
                Node.getServerStartTimes().put(serverId, System.currentTimeMillis());

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
                Node.getServerStartTimes().remove(serverId);
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
     * 更新服务器实例
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @param updates  更新的服务器信息
     * @return 更新结果
     */
    @PutMapping("/{serverId}")
    public ResponseEntity<Map<String, Object>> updateServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody ServerInstances updates) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证 serverId
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        // 验证更新数据
        if (updates == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "更新数据不能为空"));
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
            // 检查服务器是否正在运行（运行中的服务器不允许修改某些配置）
            boolean isRunning = Node.getRunningServers().containsKey(serverId);

            try {
                // 更新实例名称
                if (updates.getInstanceName() != null && !updates.getInstanceName().trim().isEmpty()) {
                    server.setInstanceName(updates.getInstanceName().trim());
                }

                // 更新文件路径（仅在服务器未运行时允许）
                if (updates.getFilePath() != null && !updates.getFilePath().trim().isEmpty()) {
                    if (isRunning) {
                        return ResponseEntity.badRequest().body(Map.of("error", "无法修改运行中服务器的文件路径"));
                    }
                    server.setFilePath(updates.getFilePath().trim());
                }

                // 更新版本
                if (updates.getVersion() != null && !updates.getVersion().trim().isEmpty()) {
                    server.setVersion(updates.getVersion().trim());
                }

                // 更新核心类型
                if (updates.getCoreType() != null && !updates.getCoreType().trim().isEmpty()) {
                    server.setCoreType(updates.getCoreType().trim());
                }

                // 更新端口
                if (updates.getPort() != null && updates.getPort() > 0 && updates.getPort() <= 65535) {
                    server.setPort(updates.getPort());
                }

                // 更新内存配置
                if (updates.getMemoryMb() != null && updates.getMemoryMb() > 0) {
                    server.setMemoryMb(updates.getMemoryMb());
                }

                // 更新JVM参数
                if (updates.getJvmArgs() != null) {
                    server.setJvmArgs(updates.getJvmArgs().trim());
                }

                // 更新时间戳
                server.setUpdatedAt(new Date());

                // 保存更新
                serverInstancesService.updateById(server);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.UPDATE_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "服务器更新成功");
                response.put("server", server);

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                log.error("更新服务器时发生错误: {}", serverId, e);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.UPDATE_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "更新服务器失败: " + e.getMessage()));
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
                Node.getServerStartTimes().remove(serverId);
                OutputStreamWriter writer = Node.getServerWriters().remove(serverId);
                closeWriter(writer);

                // 清理Query连接缓存
                removeCachedQueryConnection(serverId);

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
     * 获取服务器控制台历史日志
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 历史日志列表
     */
    @GetMapping("/{serverId}/console/history")
    public ResponseEntity<Map<String, Object>> getConsoleHistory(
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

        try {
            // 获取历史日志缓存
            List<String> logHistory = getLogCache(serverId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("serverId", serverId);
            response.put("logs", logHistory);
            response.put("count", logHistory.size());
            response.put("maxLines", MAX_CONSOLE_LOG_LINES);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("获取服务器控制台历史日志时发生错误: {}", serverId, e);
            return ResponseEntity.status(500).body(Map.of("error", "获取历史日志失败: " + e.getMessage()));
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
        try {
            command = CommandRestrictions.sanitizeMinecraftConsoleCommand(command, parseBlockedCommands());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
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
            enqueueConsoleMessage(serverId, Map.of("error", "无效的访问令牌"));
            return;
        }

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            enqueueConsoleMessage(serverId, Map.of("error", "未找到服务器"));
            return;
        }

        // 检查权限
        if (!hasServerPermission(server, accessToken)) {
            enqueueConsoleMessage(serverId, Map.of("error", "权限不足"));
            return;
        }

        // 检查服务器是否正在运行
        Process process = Node.getRunningServers().get(serverId);
        if (process == null || !process.isAlive()) {
            enqueueConsoleMessage(serverId, Map.of("error", "服务器未在运行"));
            return;
        }

        // 发送订阅成功消息
        enqueueConsoleMessage(serverId, Map.of("message", "已订阅控制台输出"));
    }

    /**
     * 添加日志到缓存
     *
     * @param serverId 服务器ID
     * @param logLine  日志行
     */
    private void addLogToCache(Integer serverId, String logLine) {
        if (serverId == null || logLine == null) {
            return;
        }

        LinkedBlockingDeque<String> logCache = CONSOLE_LOG_CACHE.computeIfAbsent(serverId,
                k -> new LinkedBlockingDeque<>(MAX_CONSOLE_LOG_LINES));

        // 保持最新的日志，超出容量时移除最旧的日志
        while (!logCache.offerLast(logLine)) {
            logCache.pollFirst();
        }
    }

    /**
     * 获取服务器控制台日志缓存
     *
     * @param serverId 服务器ID
     * @return 日志列表
     */
    private List<String> getLogCache(Integer serverId) {
        if (serverId == null) {
            return new ArrayList<>();
        }

        LinkedBlockingDeque<String> logCache = CONSOLE_LOG_CACHE.get(serverId);
        if (logCache == null) {
            return new ArrayList<>();
        }
        return new ArrayList<>(logCache);
    }

    /**
     * 清空服务器控制台日志缓存
     *
     * @param serverId 服务器ID
     */
    private void clearLogCache(Integer serverId) {
        if (serverId == null) {
            return;
        }

        CONSOLE_LOG_CACHE.remove(serverId);
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
                    // 添加到日志缓存
                    addLogToCache(serverId, line);

                    // 发送控制台输出到WebSocket
                    final String finalLine = line;
                    enqueueConsoleMessage(serverId, Map.of("line", finalLine));
                }
            } catch (IOException e) {
                // 如果进程已经终止，这是正常的
                if (!process.isAlive()) {
                    log.debug("服务器控制台输出线程正常终止: {}", serverId);
                    return;
                }

                // 否则，记录错误
                log.error("读取服务器控制台输出时发生错误: {}", serverId, e);
                String errorMsg = "读取控制台失败: " + e.getMessage();
                addLogToCache(serverId, "[ERROR] " + errorMsg);
                enqueueConsoleMessage(serverId, Map.of("error", errorMsg));
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
     * 将控制台消息加入派发队列
     *
     * @param serverId 服务器ID
     * @param payload  消息内容
     */
    private void enqueueConsoleMessage(Integer serverId, Map<String, Object> payload) {
        if (serverId == null || payload == null) {
            return;
        }

        ConsoleDispatchMessage message = new ConsoleDispatchMessage(messagingTemplate, serverId, payload);
        if (!CONSOLE_DISPATCH_QUEUE.offer(message)) {
            ConsoleDispatchMessage dropped = CONSOLE_DISPATCH_QUEUE.poll();
            if (dropped != null && log.isDebugEnabled()) {
                log.debug("控制台消息队列已满，丢弃服务器 {} 的旧消息", dropped.serverId);
            }
            if (!CONSOLE_DISPATCH_QUEUE.offer(message) && log.isWarnEnabled()) {
                log.warn("控制台消息队列已满，丢弃服务器 {} 的最新消息", serverId);
            }
        }
    }

    /**
     * 获取进程详细信息
     *
     * @param process 进程对象
     * @return 进程信息Map
     */
    private Map<String, Object> getProcessInfo(Process process) {
        Map<String, Object> processInfo = new HashMap<>();

        try {
            // 基本进程信息
            processInfo.put("alive", process.isAlive());

            // 获取进程ID
            try {
                long pid = process.pid();
                processInfo.put("pid", pid);

                // 尝试获取更详细的进程信息
                try {
                    Optional<ProcessHandle> processHandleOpt = ProcessHandle.of(pid);
                    if (processHandleOpt.isPresent()) {
                        ProcessHandle processHandle = processHandleOpt.get();
                        ProcessHandle.Info info = processHandle.info();

                        // 命令和参数
                        info.command().ifPresent(cmd -> processInfo.put("command", cmd));
                        info.arguments().ifPresent(args -> processInfo.put("arguments", Arrays.asList(args)));

                        // 启动时间
                        info.startInstant().ifPresent(start ->
                                processInfo.put("startInstant", start.toString()));

                        // CPU 时间
                        info.totalCpuDuration().ifPresent(cpu -> {
                            processInfo.put("totalCpuDurationSeconds", cpu.getSeconds());
                            processInfo.put("totalCpuDurationNanos", cpu.getNano());
                        });

                        // 用户信息
                        info.user().ifPresent(user -> processInfo.put("user", user));
                    }
                } catch (Exception e) {
                    log.debug("无法获取 ProcessHandle 信息: {}", e.getMessage());
                }

                // 获取内存和CPU使用情况（通过系统命令）
                Map<String, Object> resourceUsage = getCachedProcessResourceUsage(pid);
                if (!resourceUsage.isEmpty()) {
                    processInfo.put("resourceUsage", resourceUsage);
                }

            } catch (UnsupportedOperationException e) {
                processInfo.put("pid", null);
                log.debug("平台不支持获取 PID");
            }

        } catch (Exception e) {
            log.error("获取进程信息时发生错误", e);
            processInfo.put("error", "无法获取进程详细信息: " + e.getMessage());
        }

        return processInfo;
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

        // 设置环境变量以启用 ANSI 颜色输出
        Map<String, String> env = processBuilder.environment();
        env.put("TERM", "xterm-256color");  // 模拟支持颜色的终端
        env.put("COLORTERM", "truecolor");   // 启用真彩色支持
        // 对于某些服务器核心（如 Paper），可能需要这个
        env.put("FORCE_COLOR", "true");

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

        String trimmedScript = script.trim();

        // 获取操作系统类型
        String osName = System.getProperty("os.name");
        if (osName == null) {
            osName = "unknown";
        }

        ProcessBuilder processBuilder;
        if (osName.toLowerCase().contains("windows")) {
            // Windows 下通过 cmd /c 执行时必须过滤元字符，避免命令拼接注入
            CommandRestrictions.validateWindowsCmdScript(trimmedScript);
            processBuilder = new ProcessBuilder("cmd", "/c", trimmedScript);
        } else {
            // Unix-like 系统下避免使用 shell（bash -c），改为解析为参数列表直接执行
            List<String> unixCommand = CommandLineParser.parse(trimmedScript);
            processBuilder = new ProcessBuilder(unixCommand);
        }

        // 设置工作目录（双重保险）
        processBuilder.directory(workingDir);
        processBuilder.redirectErrorStream(true);

        // 设置环境变量以启用 ANSI 颜色输出
        Map<String, String> env = processBuilder.environment();
        env.put("TERM", "xterm-256color");
        env.put("COLORTERM", "truecolor");
        env.put("FORCE_COLOR", "true");

        log.debug("正在使用自定义脚本启动服务器 {} (工作目录: {}): {}",
                server.getId(), workingDir.getAbsolutePath(), trimmedScript);

        // 启动进程
        return processBuilder.start();
    }

    private Set<String> parseBlockedCommands() {
        if (blockedMcCommands == null || blockedMcCommands.trim().isEmpty()) {
            return Set.of();
        }
        String[] parts = blockedMcCommands.split(",");
        Set<String> set = new java.util.HashSet<>();
        for (String part : parts) {
            String s = part == null ? "" : part.trim().toLowerCase(java.util.Locale.ROOT);
            if (!s.isEmpty()) {
                set.add(s);
            }
        }
        return set;
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
                SERVER_LOCKS.remove(serverId);

                // 清理日志缓存
                clearLogCache(serverId);

                // 清理Query连接缓存
                removeCachedQueryConnection(serverId);

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

    /**
     * 获取服务器运行状态
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 服务器状态信息
     */
    @GetMapping("/{serverId}/status")
    public ResponseEntity<Map<String, Object>> getServerStatus(
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

        try {
            // 检查服务器是否正在运行
            Process process = Node.getRunningServers().get(serverId);
            boolean isRunning = process != null && process.isAlive();

            // 构建响应数据
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("serverId", serverId);
            response.put("instanceName", server.getInstanceName());
            response.put("status", server.getStatus());
            response.put("isRunning", isRunning);

            // 服务器配置信息
            Map<String, Object> config = new HashMap<>();
            config.put("version", server.getVersion());
            config.put("coreType", server.getCoreType());
            config.put("port", server.getPort());
            config.put("memoryMb", server.getMemoryMb());
            config.put("jvmArgs", server.getJvmArgs());
            config.put("filePath", server.getFilePath());
            response.put("config", config);

            // 运行时长信息（仅记录单次运行时间）
            Map<String, Object> runtime = new HashMap<>();

            // 如果服务器正在运行，添加当前运行时长
            if (isRunning) {
                Long startTime = Node.getServerStartTimes().get(serverId);
                if (startTime != null) {
                    long currentTime = System.currentTimeMillis();
                    long currentRuntimeSeconds = (currentTime - startTime) / 1000;
                    runtime.put("runtimeSeconds", currentRuntimeSeconds);
                    runtime.put("runtimeFormatted", formatRuntime(currentRuntimeSeconds));
                    runtime.put("startTime", new Date(startTime));
                }
            } else {
                // 服务器未运行，没有运行时长
                runtime.put("runtimeSeconds", 0);
                runtime.put("runtimeFormatted", "0秒");
            }

            // 进程信息
            if (isRunning && process != null) {
                Map<String, Object> processInfo = getProcessInfo(process);
                response.put("processInfo", processInfo);
            }

            response.put("runtime", runtime);

            // 时间信息
            Map<String, Object> timestamps = new HashMap<>();
            if (server.getCreatedAt() != null) {
                timestamps.put("createdAt", server.getCreatedAt());
            }
            if (server.getUpdatedAt() != null) {
                timestamps.put("updatedAt", server.getUpdatedAt());
            }
            response.put("timestamps", timestamps);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("获取服务器状态时发生错误: {}", serverId, e);
            return ResponseEntity.status(500).body(Map.of("error", "获取服务器状态失败: " + e.getMessage()));
        }
    }

    /**
     * 格式化运行时长（秒）为可读格式
     *
     * @param seconds 运行时长（秒）
     * @return 格式化后的字符串，如 "1天 2小时 30分钟 45秒"
     */
    private String formatRuntime(long seconds) {
        if (seconds < 0) {
            return "0秒";
        }

        long days = seconds / 86400;
        long hours = (seconds % 86400) / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;

        StringBuilder sb = new StringBuilder();
        if (days > 0) {
            sb.append(days).append("天 ");
        }
        if (hours > 0) {
            sb.append(hours).append("小时 ");
        }
        if (minutes > 0) {
            sb.append(minutes).append("分钟 ");
        }
        if (secs > 0 || sb.length() == 0) {
            sb.append(secs).append("秒");
        }

        return sb.toString().trim();
    }

    /**
     * 获取缓存的进程资源使用情况
     *
     * @param pid 进程ID
     * @return 资源使用情况Map
     */
    private Map<String, Object> getCachedProcessResourceUsage(long pid) {
        if (pid <= 0) {
            return Collections.emptyMap();
        }

        long now = System.currentTimeMillis();
        CachedProcessInfo cached = PROCESS_INFO_CACHE.get(pid);
        if (cached != null && now - cached.timestamp < PROCESS_INFO_CACHE_TTL_MS) {
            return new HashMap<>(cached.data);
        }

        Map<String, Object> usage = getProcessResourceUsage(pid);
        if (!usage.isEmpty()) {
            PROCESS_INFO_CACHE.put(pid, new CachedProcessInfo(new HashMap<>(usage), now));
        } else {
            PROCESS_INFO_CACHE.remove(pid);
        }

        return usage;
    }

    /**
     * 控制台消息派发任务
     */
    private record ConsoleDispatchMessage(SimpMessagingTemplate messagingTemplate, Integer serverId,
                                          Map<String, Object> payload) {

        private void dispatch() {
            messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId, payload);
        }
    }

    /**
     * 获取进程资源使用情况（内存、CPU）
     *
     * @param pid 进程ID
     * @return 资源使用情况Map
     */
    private Map<String, Object> getProcessResourceUsage(long pid) {
        Map<String, Object> resourceUsage = new HashMap<>();
        String osName = System.getProperty("os.name", "").toLowerCase();

        try {
            if (osName.contains("win")) {
                // Windows 系统
                getWindowsProcessInfo(pid, resourceUsage);
            } else if (osName.contains("linux") || osName.contains("unix") || osName.contains("mac")) {
                // Linux/Unix/macOS 系统
                getUnixProcessInfo(pid, resourceUsage);
            }
        } catch (Exception e) {
            log.debug("获取进程资源使用情况失败: {}", e.getMessage());
        }

        return resourceUsage;
    }

    /**
     * 获取 Windows 系统进程信息
     */
    private void getWindowsProcessInfo(long pid, Map<String, Object> resourceUsage) {
        try {
            // 使用 wmic 命令获取进程信息
            ProcessBuilder pb = new ProcessBuilder("wmic", "process", "where", "ProcessId=" + pid,
                    "get", "WorkingSetSize,PageFileUsage", "/format:csv");
            Process proc = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean firstLine = true;
                while ((line = reader.readLine()) != null) {
                    if (firstLine || line.trim().isEmpty()) {
                        firstLine = false;
                        continue;
                    }

                    String[] parts = line.split(",");
                    if (parts.length >= 3) {
                        try {
                            // WorkingSetSize (内存使用，字节)
                            String memoryStr = parts[parts.length - 2].trim();
                            if (!memoryStr.isEmpty() && !memoryStr.equals("WorkingSetSize")) {
                                long memoryBytes = Long.parseLong(memoryStr);
                                resourceUsage.put("memoryBytes", memoryBytes);
                                resourceUsage.put("memoryMB", memoryBytes / (1024.0 * 1024.0));
                            }

                            // PageFileUsage (虚拟内存，字节)
                            String pageFileStr = parts[parts.length - 1].trim();
                            if (!pageFileStr.isEmpty() && !pageFileStr.equals("PageFileUsage")) {
                                long pageFileBytes = Long.parseLong(pageFileStr);
                                resourceUsage.put("virtualMemoryBytes", pageFileBytes);
                                resourceUsage.put("virtualMemoryMB", pageFileBytes / (1024.0 * 1024.0));
                            }
                        } catch (NumberFormatException e) {
                            // 忽略解析错误
                        }
                    }
                }
            }

            proc.waitFor(1, TimeUnit.SECONDS);

            // 使用 PowerShell 获取 CPU 使用率
            try {
                // 使用更简单的 PowerShell 命令获取 CPU 使用率
                String psCommand = String.format(
                        "$proc = Get-Process -Id %d -ErrorAction SilentlyContinue; " +
                                "if ($proc) { $cpu = (Get-Counter \"\\Process($($proc.ProcessName))\\%% Processor Time\").CounterSamples.CookedValue; $cpu }",
                        pid);

                ProcessBuilder cpuPb = new ProcessBuilder("powershell", "-Command", psCommand);
                Process cpuProc = cpuPb.start();

                try (BufferedReader cpuReader = new BufferedReader(
                        new InputStreamReader(cpuProc.getInputStream(), StandardCharsets.UTF_8))) {
                    String cpuLine = cpuReader.readLine();
                    if (cpuLine != null && !cpuLine.trim().isEmpty()) {
                        try {
                            double cpuPercent = Double.parseDouble(cpuLine.trim());
                            // PowerShell 返回的值可能需要除以 CPU 核心数，但通常已经是百分比
                            resourceUsage.put("cpuPercent", cpuPercent);
                        } catch (NumberFormatException e) {
                            log.debug("解析CPU使用率失败: {}", cpuLine);
                        }
                    }
                }

                // 读取错误流（PowerShell 可能将输出发送到错误流）
                try (BufferedReader errorReader = new BufferedReader(
                        new InputStreamReader(cpuProc.getErrorStream(), StandardCharsets.UTF_8))) {
                    String errorLine = errorReader.readLine();
                    if (errorLine != null && !errorLine.trim().isEmpty() && !errorLine.contains("Error")) {
                        try {
                            double cpuPercent = Double.parseDouble(errorLine.trim());
                            resourceUsage.put("cpuPercent", cpuPercent);
                        } catch (NumberFormatException e) {
                            // 忽略
                        }
                    }
                }

                cpuProc.waitFor(2, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.debug("使用 PowerShell 获取 CPU 使用率失败: {}", e.getMessage());
            }
        } catch (Exception e) {
            log.debug("Windows 进程信息获取失败: {}", e.getMessage());
        }
    }

    /**
     * 获取 Unix/Linux/macOS 系统进程信息
     */
    private void getUnixProcessInfo(long pid, Map<String, Object> resourceUsage) {
        try {
            // 使用 ps 命令获取进程信息
            ProcessBuilder pb = new ProcessBuilder("ps", "-p", String.valueOf(pid), "-o",
                    "rss=,vsz=,%cpu=,etime=");
            Process proc = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean firstLine = true;
                while ((line = reader.readLine()) != null) {
                    if (firstLine) {
                        firstLine = false;
                        continue; // 跳过标题行
                    }

                    line = line.trim();
                    if (line.isEmpty()) continue;

                    // 解析 ps 输出: RSS VSZ %CPU ELAPSED
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 3) {
                        try {
                            // RSS: 物理内存使用 (KB)
                            long rssKB = Long.parseLong(parts[0]);
                            resourceUsage.put("memoryKB", rssKB);
                            resourceUsage.put("memoryMB", rssKB / 1024.0);
                            resourceUsage.put("memoryBytes", rssKB * 1024);

                            // VSZ: 虚拟内存使用 (KB)
                            long vszKB = Long.parseLong(parts[1]);
                            resourceUsage.put("virtualMemoryKB", vszKB);
                            resourceUsage.put("virtualMemoryMB", vszKB / 1024.0);
                            resourceUsage.put("virtualMemoryBytes", vszKB * 1024);

                            // %CPU: CPU 使用率
                            double cpuPercent = Double.parseDouble(parts[2]);
                            resourceUsage.put("cpuPercent", cpuPercent);

                            // ELAPSED: 运行时间
                            if (parts.length >= 4) {
                                resourceUsage.put("elapsedTime", parts[3]);
                            }
                        } catch (NumberFormatException e) {
                            // 忽略解析错误
                        }
                    }
                }
            }

            proc.waitFor(1, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.debug("Unix 进程信息获取失败: {}", e.getMessage());
        }
    }

    /**
     * 从启动脚本中提取并更新服务器的JVM参数
     *
     * @param server 服务器实例
     * @param script 启动脚本
     */
    private void updateServerJvmArgsFromScript(ServerInstances server, String script) {
        if (server == null || script == null || script.trim().isEmpty()) {
            return;
        }

        try {
            boolean needsUpdate = false;

            // 提取 -Xmx 参数
            Pattern xmxPattern = Pattern.compile("-Xmx(\\d+)([MmGgKk]?)");
            Matcher xmxMatcher = xmxPattern.matcher(script);
            if (xmxMatcher.find()) {
                String value = xmxMatcher.group(1);
                String unit = xmxMatcher.group(2).toUpperCase();

                int memoryMb = Integer.parseInt(value);
                // 转换为MB
                if ("G".equals(unit)) {
                    memoryMb *= 1024;
                } else if ("K".equals(unit)) {
                    memoryMb /= 1024;
                }

                // 更新内存配置
                if (server.getMemoryMb() == null || !server.getMemoryMb().equals(memoryMb)) {
                    server.setMemoryMb(memoryMb);
                    needsUpdate = true;
                    log.info("从启动脚本更新服务器 {} 的内存配置: {}MB", server.getId(), memoryMb);
                }
            }

            // 提取所有JVM参数（排除 -Xms 和 -Xmx）
            StringBuilder jvmArgsBuilder = new StringBuilder();
            String[] parts = script.trim().split("\\s+");
            boolean foundJar = false;

            for (String part : parts) {
                // 跳过 java 命令本身
                if ("java".equalsIgnoreCase(part)) {
                    continue;
                }

                // 遇到 -jar 后停止收集JVM参数
                if ("-jar".equalsIgnoreCase(part)) {
                    foundJar = true;
                    break;
                }

                // 跳过 -Xms 和 -Xmx 参数（这些已经单独处理）
                if (part.startsWith("-Xms") || part.startsWith("-Xmx")) {
                    continue;
                }

                // 收集其他JVM参数
                if (part.startsWith("-")) {
                    if (jvmArgsBuilder.length() > 0) {
                        jvmArgsBuilder.append(" ");
                    }
                    jvmArgsBuilder.append(part);
                }
            }

            String extractedJvmArgs = jvmArgsBuilder.toString().trim();
            if (!extractedJvmArgs.isEmpty()) {
                // 只有当提取到的参数与当前不同时才更新
                String currentJvmArgs = server.getJvmArgs();
                if (currentJvmArgs == null || !currentJvmArgs.equals(extractedJvmArgs)) {
                    server.setJvmArgs(extractedJvmArgs);
                    needsUpdate = true;
                    log.info("从启动脚本更新服务器 {} 的JVM参数: {}", server.getId(), extractedJvmArgs);
                }
            }

            // 如果有更新，保存到数据库
            if (needsUpdate) {
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);
                log.info("服务器 {} 的配置已更新到数据库", server.getId());
            }

        } catch (Exception e) {
            log.warn("从启动脚本提取JVM参数时发生错误: {}", e.getMessage());
            // 不抛出异常，继续启动流程
        }
    }

    /**
     * 获取服务器在线玩家信息
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 在线玩家信息
     */
    @GetMapping("/{serverId}/players")
    public ResponseEntity<Map<String, Object>> getOnlinePlayers(
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
        if (process == null || !process.isAlive()) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        try {
            Map<String, Object> response = new HashMap<>();

            // 首先尝试使用缓存的Query连接
            CachedQueryConnection cachedConnection = getCachedQueryConnection(serverId);
            boolean querySuccess = false;

            if (cachedConnection != null && cachedConnection.isValid()) {
                try {
                    log.debug("使用缓存的Query连接获取服务器 {} 玩家信息", serverId);
                    MinecraftServerQuery.ServerStatus status = cachedConnection.query.getFullStatus();

                    if (status != null) {
                        response = buildPlayerResponse(serverId, server, status, cachedConnection.host, cachedConnection.port, "query-cached");
                        querySuccess = true;
                        log.info("通过缓存Query连接成功获取服务器 {} 的玩家信息，在线玩家: {}/{}",
                                serverId, status.getOnlinePlayers(), status.getMaxPlayers());

                        // 记录操作日志
                        logOperation(accessToken.getMasterId(), OperationType.GET_PLAYERS, true,
                                Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                        "method", "query-cached", "host", cachedConnection.host,
                                        "port", cachedConnection.port, "onlinePlayers", status.getOnlinePlayers(),
                                        "maxPlayers", status.getMaxPlayers()));
                    }
                } catch (Exception e) {
                    log.debug("缓存的Query连接失效: {}", e.getMessage());
                    // 移除失效的缓存连接
                    removeCachedQueryConnection(serverId);
                    cachedConnection = null;
                }
            }

            // 如果缓存连接失效或不存在，尝试建立新连接
            if (!querySuccess) {
                log.debug("尝试建立新的Query连接获取服务器 {} 玩家信息", serverId);

                // 获取或分配Query端口
                int queryPort = getOrAssignQueryPort(server);

                String localIp = InetAddress.getLocalHost().getHostAddress();
                String[] hostsToTry = {localIp, Ipv4Util.LOCAL_IP};

                for (String hostToTry : hostsToTry) {
                    if (querySuccess) break;

                    MinecraftServerQuery query = new MinecraftServerQuery(hostToTry, queryPort);
                    try {
                        log.debug("尝试使用Server Query协议获取服务器 {} 玩家信息 (主机: {}, 端口: {})",
                                serverId, hostToTry, queryPort);

                        // 使用带重试的连接方法
                        if (query.connectWithRetry(2, 1000)) {
                            MinecraftServerQuery.ServerStatus status = query.getFullStatus();

                            if (status != null) {
                                response = buildPlayerResponse(serverId, server, status, hostToTry, queryPort, "query");
                                querySuccess = true;

                                // 缓存成功的连接
                                cacheQueryConnection(serverId, query, hostToTry, queryPort);

                                log.info("通过新Query连接成功获取服务器 {} 的玩家信息 (主机: {}, 端口: {})，在线玩家: {}/{}",
                                        serverId, hostToTry, queryPort, status.getOnlinePlayers(), status.getMaxPlayers());

                                // 记录操作日志
                                logOperation(accessToken.getMasterId(), OperationType.GET_PLAYERS, true,
                                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                                "method", "query", "host", hostToTry, "port", queryPort,
                                                "onlinePlayers", status.getOnlinePlayers(),
                                                "maxPlayers", status.getMaxPlayers()));
                            }
                        } else {
                            log.debug("无法连接到服务器 {} 的Query端口 {} (主机: {})", serverId, queryPort, hostToTry);
                        }
                    } catch (Exception e) {
                        log.debug("Server Query协议获取失败 (主机: {}, 端口: {}): {}", hostToTry, queryPort, e.getMessage());
                    }

                    // 如果连接失败，关闭query对象
                    if (!querySuccess) {
                        query.close();
                    }
                }
            }

            // 如果Query协议失败，尝试使用命令方式
            // if (!querySuccess) {
            //     log.debug("尝试使用命令方式获取服务器 {} 玩家信息", serverId);
            //     Map<String, Object> commandResult = getPlayersViaCommand(serverId, server, process);
            //     if (commandResult != null && Boolean.TRUE.equals(commandResult.get("success"))) {
            //         response = commandResult;
            //         querySuccess = true;
            //         log.info("通过命令方式成功获取服务器 {} 的玩家信息", serverId);
            //     }
            // }

            // 如果都失败了，返回错误信息
            if (!querySuccess) {
                int gamePort = server.getPort() != null ? server.getPort() : 25565;
                int queryPort = getOrAssignQueryPort(server);

                response.put("success", false);
                response.put("error", "无法获取玩家信息");
                response.put("players", new ArrayList<>());
                response.put("playerCount", Map.of("online", 0, "max", 0));
                response.put("troubleshooting", Map.of(
                        "queryPort", queryPort,
                        "gamePort", gamePort,
                        "suggestions", List.of(
                                "检查server.properties中enable-query=true",
                                "确认query.port=" + queryPort,
                                "检查防火墙是否开放Query端口",
                                "确认服务器版本支持Query协议",
                                "等待服务器完全启动后再试（启动后等待30秒）"
                        )
                ));

                log.warn("无法获取服务器 {} 的玩家信息，Query端口: {}", serverId, queryPort);
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("获取服务器 {} 在线玩家信息时发生错误", serverId, e);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", "获取玩家信息失败: " + e.getMessage());
            errorResponse.put("players", new ArrayList<>());
            errorResponse.put("playerCount", Map.of("online", 0, "max", 0));

            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * 诊断Query连接问题
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 诊断结果
     */
    @GetMapping("/{serverId}/query-diagnostic")
    public ResponseEntity<Map<String, Object>> queryDiagnostic(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
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

        Map<String, Object> diagnostic = new HashMap<>();

        try {
            int gamePort = getServerPort(server);
            int queryPort = getOrAssignQueryPort(server);

            diagnostic.put("serverId", serverId);
            diagnostic.put("gamePort", gamePort);
            diagnostic.put("queryPort", queryPort);
            diagnostic.put("serverRunning", Node.getRunningServers().containsKey(serverId));

            // 检查server.properties文件
            File serverPropertiesFile = new File(server.getFilePath(), "server.properties");
            Map<String, Object> propertiesInfo = new HashMap<>();
            propertiesInfo.put("exists", serverPropertiesFile.exists());

            if (serverPropertiesFile.exists()) {
                try {
                    Properties properties = new Properties();
                    try (FileInputStream fis = new FileInputStream(serverPropertiesFile)) {
                        properties.load(fis);
                    }
                    propertiesInfo.put("enable-query", properties.getProperty("enable-query"));
                    propertiesInfo.put("query.port", properties.getProperty("query.port"));
                    propertiesInfo.put("server-port", properties.getProperty("server-port"));
                } catch (Exception e) {
                    propertiesInfo.put("readError", e.getMessage());
                }
            }
            diagnostic.put("serverProperties", propertiesInfo);

            // 测试Query连接
            // 获取本机IP地址
            String localIp = InetAddress.getLocalHost().getHostAddress();
            Map<String, Object> connectionTests = new HashMap<>();
            String[] hostsToTest = {localIp, Ipv4Util.LOCAL_IP};

            for (String host : hostsToTest) {
                try {
                    Map<String, Object> testResult = MinecraftServerQuery.detailedConnectionTest(host, queryPort);
                    connectionTests.put(host, testResult);
                } catch (Exception e) {
                    Map<String, Object> errorResult = new HashMap<>();
                    errorResult.put("host", host);
                    errorResult.put("port", queryPort);
                    errorResult.put("error", e.getMessage());
                    errorResult.put("socketCreated", false);
                    connectionTests.put(host, errorResult);
                }
            }
            diagnostic.put("connectionTests", connectionTests);

            // 提供建议
            List<String> suggestions = new ArrayList<>();
            if (!serverPropertiesFile.exists()) {
                suggestions.add("server.properties文件不存在，请重启服务器以自动创建");
            } else {
                Properties props = new Properties();
                try (FileInputStream fis = new FileInputStream(serverPropertiesFile)) {
                    props.load(fis);
                    if (!"true".equals(props.getProperty("enable-query"))) {
                        suggestions.add("在server.properties中设置 enable-query=true");
                    }
                    if (!String.valueOf(queryPort).equals(props.getProperty("query.port"))) {
                        suggestions.add("在server.properties中设置 query.port=" + queryPort);
                    }
                } catch (Exception e) {
                    suggestions.add("无法读取server.properties文件: " + e.getMessage());
                }
            }

            if (!Node.getRunningServers().containsKey(serverId)) {
                suggestions.add("服务器未运行，请先启动服务器");
            }

            boolean anyConnectionWorked = connectionTests.values().stream()
                    .anyMatch(test -> Boolean.TRUE.equals(((Map<?, ?>) test).get("handshakeSuccess")));

            if (!anyConnectionWorked) {
                suggestions.add("等待服务器完全启动后再试（启动后等待30秒）");
                suggestions.add("检查防火墙是否开放UDP端口 " + queryPort);
                suggestions.add("尝试重启服务器以应用Query配置");
            }

            diagnostic.put("suggestions", suggestions);
            diagnostic.put("timestamp", System.currentTimeMillis());

            return ResponseEntity.ok(diagnostic);

        } catch (Exception e) {
            log.error("Query诊断失败", e);
            diagnostic.put("error", "诊断失败: " + e.getMessage());
            return ResponseEntity.status(500).body(diagnostic);
        }
    }

    /**
     * 对玩家执行操作
     *
     * @param token      访问令牌
     * @param serverId   服务器实例ID
     * @param playerName 玩家名称
     * @param request    操作请求
     * @return 操作结果
     */
    @PostMapping("/{serverId}/players/{playerName}/action")
    public ResponseEntity<Map<String, Object>> playerAction(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @PathVariable String playerName,
            @RequestBody Map<String, String> request) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        // 验证参数
        if (serverId == null || serverId <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "无效的服务器ID"));
        }

        if (playerName == null || playerName.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "玩家名称不能为空"));
        }

        if (request == null || !request.containsKey("action")) {
            return ResponseEntity.badRequest().body(Map.of("error", "操作类型不能为空"));
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
        if (process == null || !process.isAlive()) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        String action = request.get("action");
        String reason = request.getOrDefault("reason", "");

        // 构建命令
        String command = buildPlayerCommand(action, playerName, reason);
        if (command == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "不支持的操作类型: " + action));
        }

        // 使用锁防止并发命令发送
        synchronized (getServerLock(serverId)) {
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

                // 发送命令
                writer.write(command + "\n");
                writer.flush();

                log.info("对玩家 {} 执行操作: {} (服务器: {})", playerName, action, serverId);

                // 记录操作日志
                logOperation(accessToken.getMasterId(), OperationType.PLAYER_ACTION, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                "action", action, "player", playerName, "command", command));

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "操作执行成功");
                response.put("action", action);
                response.put("player", playerName);
                response.put("command", command);

                return ResponseEntity.ok(response);

            } catch (Exception e) {
                log.error("对玩家 {} 执行操作 {} 时发生错误 (服务器: {})", playerName, action, serverId, e);

                logOperation(accessToken.getMasterId(), OperationType.PLAYER_ACTION, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                "action", action, "player", playerName, "error", e.getMessage()));

                return ResponseEntity.status(500).body(Map.of("error", "操作执行失败: " + e.getMessage()));
            }
        }
    }

    /**
     * 构建玩家操作命令
     */
    private String buildPlayerCommand(String action, String playerName, String reason) {
        switch (action.toLowerCase()) {
            case "kick":
                return reason.isEmpty() ?
                        "kick " + playerName :
                        "kick " + playerName + " " + reason;
            case "ban":
                return reason.isEmpty() ?
                        "ban " + playerName :
                        "ban " + playerName + " " + reason;
            case "ban-ip":
                return reason.isEmpty() ?
                        "ban-ip " + playerName :
                        "ban-ip " + playerName + " " + reason;
            case "pardon":
                return "pardon " + playerName;
            case "pardon-ip":
                return "pardon-ip " + playerName;
            case "op":
                return "op " + playerName;
            case "deop":
                return "deop " + playerName;
            case "whitelist-add":
                return "whitelist add " + playerName;
            case "whitelist-remove":
                return "whitelist remove " + playerName;
            case "gamemode-creative":
                return "gamemode creative " + playerName;
            case "gamemode-survival":
                return "gamemode survival " + playerName;
            case "gamemode-adventure":
                return "gamemode adventure " + playerName;
            case "gamemode-spectator":
                return "gamemode spectator " + playerName;
            case "tp-to-spawn":
                return "tp " + playerName + " ~ ~ ~";
            default:
                return null;
        }
    }

    /**
     * 获取或分配Query端口
     *
     * @param server 服务器实例
     * @return Query端口号
     */
    private int getOrAssignQueryPort(ServerInstances server) {
        if (server == null) {
            return QUERY_PORT_RANGE_START;
        }

        // 首先检查server.properties中是否已配置Query端口
        File serverPropertiesFile = new File(server.getFilePath(), "server.properties");
        if (serverPropertiesFile.exists()) {
            try {
                Properties properties = new Properties();
                try (FileInputStream fis = new FileInputStream(serverPropertiesFile)) {
                    properties.load(fis);
                }
                String queryPortStr = properties.getProperty("query.port");
                if (queryPortStr != null && !queryPortStr.trim().isEmpty()) {
                    try {
                        int existingPort = Integer.parseInt(queryPortStr.trim());
                        if (existingPort > 0 && existingPort <= 65535) {
                            log.debug("服务器 {} 使用已配置的Query端口: {}", server.getId(), existingPort);
                            return existingPort;
                        }
                    } catch (NumberFormatException e) {
                        log.debug("无效的Query端口配置: {}", queryPortStr);
                    }
                }
            } catch (Exception e) {
                log.debug("读取server.properties失败: {}", e.getMessage());
            }
        }

        // 如果没有配置或配置无效，分配一个可用端口
        return findAvailableQueryPort();
    }

    /**
     * 获取服务器端口号
     **/
    private int getServerPort(ServerInstances server) {
        File serverPropertiesFile = new File(server.getFilePath(), "server.properties");
        if (serverPropertiesFile.exists()) {
            try {
                Properties properties = new Properties();
                try (FileInputStream fis = new FileInputStream(serverPropertiesFile)) {
                    properties.load(fis);
                }
                String serverPortStr = properties.getProperty("server.port");
                if (serverPortStr != null && !serverPortStr.trim().isEmpty()) {
                    try {
                        int existingPort = Integer.parseInt(serverPortStr.trim());
                        if (existingPort > 0 && existingPort <= 65535) {
                            log.debug("服务器 {} 使用已配置的服务器端口: {}", server.getId(), existingPort);
                            return existingPort;
                        }
                    } catch (NumberFormatException e) {
                        log.debug("无效的服务器端口配置: {}", serverPortStr);
                    }
                }
            } catch (Exception e) {
                log.debug("读取server.properties失败: {}", e.getMessage());
            }
        }
        return 25565;
    }

    /**
     * 查找可用的Query端口
     *
     * @return 可用的端口号
     */
    private int findAvailableQueryPort() {
        // 使用随机起始点避免端口冲突
        Random random = new Random();
        int startPort = QUERY_PORT_RANGE_START + random.nextInt(QUERY_PORT_RANGE_END - QUERY_PORT_RANGE_START);

        // 从随机起始点开始查找可用端口
        for (int i = 0; i < (QUERY_PORT_RANGE_END - QUERY_PORT_RANGE_START); i++) {
            int port = startPort + i;
            if (port > QUERY_PORT_RANGE_END) {
                port = QUERY_PORT_RANGE_START + (port - QUERY_PORT_RANGE_END - 1);
            }

            if (isPortAvailable(port)) {
                log.debug("分配可用Query端口: {}", port);
                return port;
            }
        }

        // 如果都不可用，返回默认端口
        log.warn("无法找到可用的Query端口，使用默认端口: {}", QUERY_PORT_RANGE_START);
        return QUERY_PORT_RANGE_START;
    }

    /**
     * 检查端口是否可用
     *
     * @param port 端口号
     * @return 是否可用
     */
    private boolean isPortAvailable(int port) {
        try (java.net.ServerSocket serverSocket = new java.net.ServerSocket(port)) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取缓存的Query连接
     *
     * @param serverId 服务器ID
     * @return 缓存的连接，如果不存在或已过期则返回null
     */
    private CachedQueryConnection getCachedQueryConnection(Integer serverId) {
        if (serverId == null) {
            return null;
        }

        CachedQueryConnection cached = QUERY_CONNECTION_CACHE.get(serverId);
        if (cached != null) {
            if (System.currentTimeMillis() - cached.timestamp < QUERY_CONNECTION_TTL_MS) {
                return cached;
            } else {
                // 缓存已过期，移除并关闭连接
                removeCachedQueryConnection(serverId);
            }
        }
        return null;
    }

    /**
     * 缓存Query连接
     *
     * @param serverId 服务器ID
     * @param query    Query对象
     * @param host     主机地址
     * @param port     端口号
     */
    private void cacheQueryConnection(Integer serverId, MinecraftServerQuery query, String host, int port) {
        if (serverId == null || query == null) {
            return;
        }

        // 移除旧的缓存连接
        removeCachedQueryConnection(serverId);

        // 添加新的缓存连接
        CachedQueryConnection cached = new CachedQueryConnection(query, host, port, System.currentTimeMillis());
        QUERY_CONNECTION_CACHE.put(serverId, cached);

        log.debug("缓存服务器 {} 的Query连接 (主机: {}, 端口: {})", serverId, host, port);
    }

    /**
     * 移除缓存的Query连接
     *
     * @param serverId 服务器ID
     */
    private void removeCachedQueryConnection(Integer serverId) {
        if (serverId == null) {
            return;
        }

        CachedQueryConnection cached = QUERY_CONNECTION_CACHE.remove(serverId);
        if (cached != null && cached.query != null) {
            try {
                cached.query.close();
                log.debug("关闭服务器 {} 的缓存Query连接", serverId);
            } catch (Exception e) {
                log.debug("关闭Query连接时发生错误: {}", e.getMessage());
            }
        }
    }

    /**
     * 清理所有Query连接
     */
    private void cleanupQueryConnections() {
        log.info("清理所有Query连接缓存...");

        for (Map.Entry<Integer, CachedQueryConnection> entry : QUERY_CONNECTION_CACHE.entrySet()) {
            try {
                if (entry.getValue() != null && entry.getValue().query != null) {
                    entry.getValue().query.close();
                }
            } catch (Exception e) {
                log.debug("清理Query连接时发生错误: {}", e.getMessage());
            }
        }

        QUERY_CONNECTION_CACHE.clear();
        log.info("Query连接缓存清理完成");
    }

    /**
     * 构建玩家信息响应
     *
     * @param serverId 服务器ID
     * @param server   服务器实例
     * @param status   服务器状态
     * @param host     主机地址
     * @param port     端口号
     * @param method   获取方法
     * @return 响应Map
     */
    private Map<String, Object> buildPlayerResponse(Integer serverId, ServerInstances server,
                                                    MinecraftServerQuery.ServerStatus status,
                                                    String host, int port, String method) {
        Map<String, Object> response = new HashMap<>();

        response.put("success", true);
        response.put("serverId", serverId);
        response.put("method", method);
        response.put("queryHost", host);
        response.put("queryPort", port);
        response.put("serverInfo", Map.of(
                "motd", status.getMotd() != null ? status.getMotd() : "",
                "version", status.getVersion() != null ? status.getVersion() : "",
                "gameType", status.getGameType() != null ? status.getGameType() : "",
                "map", status.getMap() != null ? status.getMap() : "",
                "plugins", status.getPlugins() != null ? status.getPlugins() : ""
        ));

        // 玩家信息
        List<String> playerNames = status.getPlayerList();
        List<Map<String, Object>> players = new ArrayList<>();

        for (String playerName : playerNames) {
            Map<String, Object> playerInfo = new HashMap<>();
            playerInfo.put("name", playerName);
            playerInfo.put("joinTime", System.currentTimeMillis()); // 暂时使用当前时间
            players.add(playerInfo);
        }

        response.put("players", players);
        response.put("playerCount", Map.of(
                "online", status.getOnlinePlayers(),
                "max", status.getMaxPlayers()
        ));

        return response;
    }

    /**
     * 确保服务器启用Query功能
     *
     * @param server 服务器实例
     */
    private void ensureQueryEnabled(ServerInstances server) {
        if (server == null || server.getFilePath() == null) {
            return;
        }

        try {
            File serverPropertiesFile = new File(server.getFilePath(), "server.properties");
            if (!serverPropertiesFile.exists()) {
                log.info("服务器 {} 的 server.properties 文件不存在，创建默认配置", server.getId());
                createDefaultServerProperties(serverPropertiesFile, server);
                return;
            }

            // 读取现有配置
            Properties properties = new Properties();
            try (FileInputStream fis = new FileInputStream(serverPropertiesFile)) {
                properties.load(fis);
            }

            // 检查并设置Query相关配置
            boolean needUpdate = false;

            // 启用Query
            if (!"true".equals(properties.getProperty("enable-query"))) {
                properties.setProperty("enable-query", "true");
                needUpdate = true;
                log.debug("服务器 {} 启用Query功能", server.getId());
            }

            // 设置Query端口（如果没有配置则分配一个）
            int gamePort = getServerPort(server);
            String currentQueryPort = properties.getProperty("query.port");
            int queryPort;

            if (currentQueryPort != null && !currentQueryPort.trim().isEmpty()) {
                try {
                    queryPort = Integer.parseInt(currentQueryPort.trim());
                    if (queryPort <= 0 || queryPort > 65535) {
                        queryPort = findAvailableQueryPort();
                        properties.setProperty("query.port", String.valueOf(queryPort));
                        needUpdate = true;
                        log.debug("服务器 {} 的Query端口配置无效，重新分配: {}", server.getId(), queryPort);
                    }
                } catch (NumberFormatException e) {
                    queryPort = findAvailableQueryPort();
                    properties.setProperty("query.port", String.valueOf(queryPort));
                    needUpdate = true;
                    log.debug("服务器 {} 的Query端口配置格式错误，重新分配: {}", server.getId(), queryPort);
                }
            } else {
                queryPort = findAvailableQueryPort();
                properties.setProperty("query.port", String.valueOf(queryPort));
                needUpdate = true;
                log.debug("服务器 {} 设置Query端口: {}", server.getId(), queryPort);
            }

            // 如果需要更新，写回文件
            if (needUpdate) {
                // 备份原文件
                File backupFile = new File(serverPropertiesFile.getParent(), "server.properties.backup");
                try {
                    Files.copy(serverPropertiesFile.toPath(), backupFile.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception e) {
                    log.warn("备份server.properties失败: {}", e.getMessage());
                }

                try (FileOutputStream fos = new FileOutputStream(serverPropertiesFile)) {
                    properties.store(fos, "Updated by Endless-Node to enable Query - " + new Date());
                }
                log.info("已为服务器 {} 启用Query功能，游戏端口: {}, Query端口: {}", server.getId(), gamePort, queryPort);
            } else {
                log.debug("服务器 {} 的Query配置已正确", server.getId());
            }

        } catch (Exception e) {
            log.error("配置服务器 {} 的Query功能时发生错误", server.getId(), e);
        }
    }

    /**
     * 创建默认的server.properties文件
     */
    private void createDefaultServerProperties(File serverPropertiesFile, ServerInstances server) {
        try {
            Properties properties = new Properties();

            // 基本配置
            int gamePort = getServerPort(server);
            int queryPort = findAvailableQueryPort();

            properties.setProperty("server-port", String.valueOf(gamePort));
            properties.setProperty("enable-query", "true");
            properties.setProperty("query.port", String.valueOf(queryPort));
            properties.setProperty("gamemode", "survival");
            properties.setProperty("difficulty", "easy");
            properties.setProperty("max-players", "20");
            properties.setProperty("online-mode", "true");
            properties.setProperty("white-list", "false");
            properties.setProperty("motd", "A Minecraft Server");

            try (FileOutputStream fos = new FileOutputStream(serverPropertiesFile)) {
                properties.store(fos, "Default server.properties created by Endless-Node - " + new Date());
            }

            log.info("已为服务器 {} 创建默认server.properties，游戏端口: {}, Query端口: {}",
                    server.getId(), gamePort, queryPort);

        } catch (Exception e) {
            log.error("创建默认server.properties失败", e);
        }
    }

    /**
     * 通过命令方式获取玩家信息（备用方法）
     */
    private Map<String, Object> getPlayersViaCommand(Integer serverId, ServerInstances server, Process process) {
        try {
            // 发送list命令
            OutputStreamWriter writer;
            if (Node.getServerWriters().containsKey(serverId)) {
                writer = Node.getServerWriters().get(serverId);
            } else {
                OutputStream outputStream = process.getOutputStream();
                if (outputStream == null) {
                    return null;
                }
                writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
                Node.getServerWriters().put(serverId, writer);
            }

            // 发送list命令
            writer.write("list\n");
            writer.flush();

            Thread.sleep(1000);

            // 从控制台日志缓存中查找最近的list命令输出
            List<String> recentLogs = getLogCache(serverId);
            String listOutput = null;

            // 从最新的日志中查找list命令的输出
            for (int i = recentLogs.size() - 1; i >= Math.max(0, recentLogs.size() - 10); i--) {
                String log = recentLogs.get(i);
                if (log.contains("players online") || log.contains("There are") ||
                        log.matches(".*\\d+/\\d+.*players.*")) {
                    listOutput = log;
                    break;
                }
            }

            if (listOutput != null) {
                return parseListCommandOutput(listOutput, serverId, server);
            }

        } catch (Exception e) {
            log.debug("通过命令获取玩家信息失败: {}", e.getMessage());
        }

        return null;
    }

    /**
     * 解析list命令的输出
     */
    private Map<String, Object> parseListCommandOutput(String output, Integer serverId, ServerInstances server) {
        try {
            Map<String, Object> response = new HashMap<>();
            List<Map<String, Object>> players = new ArrayList<>();

            // 解析不同格式的list命令输出
            // 格式1: "There are 2 of a max of 20 players online: player1, player2"
            // 格式2: "There are 2/20 players online: player1, player2"
            // 格式3: "Players online (2/20): player1, player2"

            Pattern pattern1 = Pattern.compile(
                    "There are (\\d+) of a max of (\\d+) players online:?\\s*(.*)");
            Pattern pattern2 = Pattern.compile(
                    "There are (\\d+)/(\\d+) players online:?\\s*(.*)");
            Pattern pattern3 = Pattern.compile(
                    "Players online \\((\\d+)/(\\d+)\\):?\\s*(.*)");

            Matcher matcher = pattern1.matcher(output);
            if (!matcher.find()) {
                matcher = pattern2.matcher(output);
                if (!matcher.find()) {
                    matcher = pattern3.matcher(output);
                }
            }

            if (matcher.find()) {
                int onlinePlayers = Integer.parseInt(matcher.group(1));
                int maxPlayers = Integer.parseInt(matcher.group(2));
                String playerList = matcher.group(3).trim();

                // 解析玩家名称
                if (!playerList.isEmpty() && !playerList.equals("")) {
                    String[] playerNames = playerList.split(",\\s*");
                    for (String playerName : playerNames) {
                        playerName = playerName.trim();
                        if (!playerName.isEmpty()) {
                            Map<String, Object> playerInfo = new HashMap<>();
                            playerInfo.put("name", playerName);
                            playerInfo.put("joinTime", System.currentTimeMillis());
                            players.add(playerInfo);
                        }
                    }
                }

                response.put("success", true);
                response.put("serverId", serverId);
                response.put("method", "command");
                response.put("serverInfo", Map.of(
                        "motd", server.getInstanceName() != null ? server.getInstanceName() : "",
                        "version", server.getVersion() != null ? server.getVersion() : "",
                        "coreType", server.getCoreType() != null ? server.getCoreType() : ""
                ));
                response.put("players", players);
                response.put("playerCount", Map.of("online", onlinePlayers, "max", maxPlayers));

                return response;
            }

        } catch (Exception e) {
            log.debug("解析list命令输出失败: {}", e.getMessage());
        }

        return null;
    }

    /**
     * 缓存的进程信息
     */
    private record CachedProcessInfo(Map<String, Object> data, long timestamp) {
    }

    /**
     * 缓存的Query连接信息
     */
    private static class CachedQueryConnection {
        final MinecraftServerQuery query;
        final String host;
        final int port;
        final long timestamp;

        public CachedQueryConnection(MinecraftServerQuery query, String host, int port, long timestamp) {
            this.query = query;
            this.host = host;
            this.port = port;
            this.timestamp = timestamp;
        }

        /**
         * 检查连接是否有效
         */
        public boolean isValid() {
            if (query == null) {
                return false;
            }

            // 检查是否超时
            return System.currentTimeMillis() - timestamp < QUERY_CONNECTION_TTL_MS;

        }
    }

    /**
     * 玩家信息类
     */
    @Data
    public static class PlayerInfo {
        private String playerName;
        private String uuid;
        private long joinTime;
        private String ipAddress;

        public PlayerInfo(String playerName, String uuid, long joinTime, String ipAddress) {
            this.playerName = playerName;
            this.uuid = uuid;
            this.joinTime = joinTime;
            this.ipAddress = ipAddress;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("playerName", playerName);
            map.put("uuid", uuid);
            map.put("joinTime", new Date(joinTime));
            map.put("ipAddress", ipAddress);
            map.put("onlineTime", System.currentTimeMillis() - joinTime);
            return map;
        }
    }
}
