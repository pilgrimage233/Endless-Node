package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.common.constant.OperationType;
import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.OperationLogs;
import cc.endmc.endlessnode.domain.ServerInstances;
import cc.endmc.endlessnode.manage.AsyncManager;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.*;
import cc.endmc.endlessnode.util.CommandRestrictions;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * 服务器实例控制器 — 仅负责 HTTP 端点定义、权限校验和委托调用。
 * 进程管理、控制台日志、Query 连接等逻辑已拆分到独立 Service。
 */
@Slf4j
@RestController
@RequestMapping("/api/servers")
@RequiredArgsConstructor
public class ServerController {

    private final AccessTokensService accessTokensService;
    private final ServerInstancesService serverInstancesService;
    private final OperationLogsService operationLogsService;
    private final ConsoleLogService consoleLogService;
    private final QueryConnectionManager queryManager;
    private final MinecraftProcessManager processManager;
    private final BackupService backupService;

    private static final int MAX_INSTANCES_PER_USER = 20;

    @Value("${endless.security.blocked-mc-commands:op,stop}")
    private String blockedMcCommands;

    @PreDestroy
    public void cleanup() {
        log.info("应用正在关闭，开始清理运行中的服务器进程...");
        Set<Integer> runningIds = new HashSet<>(Node.getRunningServers().keySet());
        if (runningIds.isEmpty()) {
            log.info("没有运行中的服务器进程需要清理");
            return;
        }
        for (Integer serverId : runningIds) {
            Process process = Node.getRunningServers().get(serverId);
            if (process == null || !process.isAlive()) {
                processManager.cleanupServer(serverId);
                continue;
            }
            try {
                processManager.stopConsoleThread(serverId);
                try {
                    OutputStreamWriter w = Node.getServerWriters().get(serverId);
                    if (w != null) { w.write("stop\n"); w.flush(); }
                } catch (Exception e) { log.warn("向服务器 {} 发送stop命令失败: {}", serverId, e.getMessage()); }
                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }
                processManager.cleanupServer(serverId);
                updateServerStatus(serverId, "STOPPED");
            } catch (Exception e) {
                log.error("停止服务器 {} 时发生错误", serverId, e);
                process.destroyForcibly();
                processManager.cleanupServer(serverId);
            }
        }
        log.info("所有服务器进程清理完成");
        queryManager.cleanupAll();
    }

    // ==================== 服务器列表 ====================

    @GetMapping("/list")
    public ResponseEntity<Map<String, Object>> listServers(@RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token) {
        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();

        try {
            List<ServerInstances> instances = serverInstancesService.lambdaQuery()
                    .eq(ServerInstances::getCreatedBy, at.getMasterUuid()).list();
            List<ServerInstances> toUpdate = new ArrayList<>();
            for (ServerInstances inst : instances) {
                if (inst != null && inst.getId() != null) {
                    Process proc = Node.getRunningServers().get(inst.getId());
                    boolean processAlive = proc != null && proc.isAlive();
                    if (proc != null && !proc.isAlive()) {
                        // 进程已退出但缓存未清理
                        processManager.cleanupServer(inst.getId());
                    }
                    String currentStatus = inst.getStatus();
                    if (processAlive && ("STOPPED".equals(currentStatus))) {
                        inst.setStatus("RUNNING");
                        toUpdate.add(inst);
                    } else if (!processAlive && !"STOPPED".equals(currentStatus)) {
                        inst.setStatus("STOPPED");
                        toUpdate.add(inst);
                    }
                }
            }
            if (!toUpdate.isEmpty()) {
                serverInstancesService.updateBatchById(toUpdate);
            }
            return ResponseEntity.ok(Map.of("servers", instances));
        } catch (Exception e) {
            log.error("获取用户服务器列表时发生错误: {}", at.getMasterUuid(), e);
            return serverError("获取服务器列表失败");
        }
    }

    // ==================== 创建 ====================

    @PostMapping("/create")
    public ResponseEntity<Map<String, Object>> createServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @RequestBody ServerInstances server) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        if (server == null) return badRequest("服务器实例信息不能为空");
        if (server.getInstanceName() == null || server.getInstanceName().trim().isEmpty())
            return badRequest("服务器实例名称不能为空");
        if (server.getFilePath() == null || server.getFilePath().trim().isEmpty())
            return badRequest("服务器文件路径不能为空");

        try {
            long count = serverInstancesService.lambdaQuery()
                    .eq(ServerInstances::getCreatedBy, at.getMasterUuid()).count();
            if (count >= MAX_INSTANCES_PER_USER) return badRequest("已达到最大实例数量限制");

            if (server.getMemoryMb() == null || server.getMemoryMb() <= 0) server.setMemoryMb(1024);
            if (server.getJvmArgs() == null || server.getJvmArgs().trim().isEmpty())
                server.setJvmArgs("-XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200");

            // 端口分配：指定端口时检测冲突，未指定时自动分配
            int port;
            if (server.getPort() != null && server.getPort() > 0) {
                port = server.getPort();
            } else {
                port = findAvailablePort(at.getMasterUuid());
                if (port == -1) return badRequest("无法自动分配可用端口（范围 25565-25665）");
            }
            server.setPort(port);
            Long portConflict = serverInstancesService.lambdaQuery()
                    .eq(ServerInstances::getCreatedBy, at.getMasterUuid())
                    .eq(ServerInstances::getPort, port)
                    .count();
            if (portConflict > 0) {
                return badRequest("端口 " + port + " 已被其他服务器实例占用");
            }

            server.setCreatedBy(at.getMasterUuid());
            server.setCreatedAt(new Date());
            server.setStatus("STOPPED");

            serverInstancesService.save(server);
            logOperation(at.getMasterId(), OperationType.CREATE_SERVER, true,
                    Map.of("instanceId", server.getId(), "instanceName", server.getInstanceName()));
            return ResponseEntity.ok(Map.of("success", true, "serverId", server.getId()));
        } catch (Exception e) {
            log.error("为用户创建服务器时发生错误: {}", at.getMasterUuid(), e);
            logOperation(at.getMasterId(), OperationType.CREATE_SERVER, false, Map.of("error", e.getMessage()));
            return serverError("创建服务器失败: " + e.getMessage());
        }
    }

    // ==================== 启动 ====================

    @PostMapping("/{serverId}/start")
    public ResponseEntity<Map<String, Object>> startServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> startScript) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        synchronized (processManager.getServerLock(serverId)) {
            Process existing = Node.getRunningServers().get(serverId);
            if (existing != null) {
                if (existing.isAlive()) {
                    return badRequest("服务器已经在运行中");
                }
                // 进程已退出但缓存未清理，清除残留状态
                processManager.cleanupServer(serverId);
            }

            Process process = null;
            try {
                String script = extractScript(startScript);
                if (script != null)
                    processManager.updateJvmArgsFromScript(server, script, serverInstancesService);
                queryManager.ensureQueryEnabled(server);

                // 启动前检测游戏端口是否被占用
                int gamePort = server.getPort() != null ? server.getPort() : 25565;
                if (!processManager.isPortAvailable(gamePort)) {
                    return badRequest("端口 " + gamePort + " 已被占用，请先关闭占用该端口的进程或修改服务器端口");
                }

                process = script != null
                        ? processManager.startServerWithScript(server, script)
                        : processManager.startServer(server);

                if (process == null || !process.isAlive()) throw new IOException("进程启动失败");

                Node.getRunningServers().put(serverId, process);
                Node.getServerStartTimes().put(serverId, System.currentTimeMillis());
                consoleLogService.registerServer(serverId, server.getFilePath());
                processManager.startConsoleThread(serverId, process);

                // 立即标记为 STARTING，后台健康检查确认就绪后更新为 RUNNING
                server.setStatus("STARTING");
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);

                // 后台健康检查：轮询游戏端口，最多等 120 秒
                processManager.waitForServerReady(server, serverInstancesService, 120, 3000);

                logOperation(at.getMasterId(), OperationType.START_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));
                return ResponseEntity.ok(Map.of("success", true, "message", "服务器启动中，正在等待就绪"));
            } catch (Exception e) {
                log.error("启动服务器时发生错误: {}", serverId, e);
                if (process != null) process.destroyForcibly();
                processManager.cleanupServer(serverId);
                logOperation(at.getMasterId(), OperationType.START_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));
                return serverError("启动服务器失败: " + e.getMessage());
            }
        }
    }

    // ==================== 停止 ====================

    @PostMapping("/{serverId}/stop")
    public ResponseEntity<Map<String, Object>> stopServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> stopScript) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        synchronized (processManager.getServerLock(serverId)) {
            Process process = Node.getRunningServers().get(serverId);
            if (process == null || !process.isAlive()) {
                processManager.cleanupServer(serverId);
                return badRequest("服务器未在运行");
            }

            try {
                processManager.stopConsoleThread(serverId);
                String script = extractScript(stopScript);
                if (script != null) {
                    processManager.executeStopScript(server, script);
                } else {
                    process.destroy();
                }
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }
                processManager.cleanupServer(serverId);
                queryManager.remove(serverId);
                updateServerStatus(serverId, "STOPPED");

                logOperation(at.getMasterId(), OperationType.STOP_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));
                return ResponseEntity.ok(Map.of("success", true, "message", "服务器停止成功"));
            } catch (Exception e) {
                log.error("停止服务器时发生错误: {}", serverId, e);
                logOperation(at.getMasterId(), OperationType.STOP_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));
                return serverError("停止服务器失败: " + e.getMessage());
            }
        }
    }

    // ==================== 重启 ====================

    @PostMapping("/{serverId}/restart")
    public ResponseEntity<Map<String, Object>> restartServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> scripts) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        synchronized (processManager.getServerLock(serverId)) {
            Process process = Node.getRunningServers().get(serverId);
            if (process == null) return badRequest("服务器未在运行");

            Process newProcess = null;
            try {
                processManager.stopConsoleThread(serverId);
                String stopScript = scripts != null ? scripts.get("stopScript") : null;
                if (stopScript != null && !stopScript.trim().isEmpty()) {
                    processManager.executeStopScript(server, stopScript);
                } else {
                    process.destroy();
                }
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }
                processManager.cleanupServer(serverId);
                queryManager.remove(serverId);

                Thread.sleep(5000);

                String startScript = scripts != null ? scripts.get("startScript") : null;
                if (startScript != null && !startScript.trim().isEmpty())
                    processManager.updateJvmArgsFromScript(server, startScript, serverInstancesService);
                queryManager.ensureQueryEnabled(server);

                newProcess = (startScript != null && !startScript.trim().isEmpty())
                        ? processManager.startServerWithScript(server, startScript)
                        : processManager.startServer(server);

                if (newProcess == null || !newProcess.isAlive()) throw new IOException("重启后进程启动失败");

                Node.getRunningServers().put(serverId, newProcess);
                Node.getServerStartTimes().put(serverId, System.currentTimeMillis());
                processManager.startConsoleThread(serverId, newProcess);

                server.setStatus("RUNNING");
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);

                logOperation(at.getMasterId(), OperationType.RESTART_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));
                return ResponseEntity.ok(Map.of("success", true, "message", "服务器重启成功"));
            } catch (Exception e) {
                log.error("重启服务器时发生错误: {}", serverId, e);
                if (newProcess != null) newProcess.destroyForcibly();
                processManager.cleanupServer(serverId);
                updateServerStatus(serverId, "STOPPED");
                logOperation(at.getMasterId(), OperationType.RESTART_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));
                return serverError("重启服务器失败: " + e.getMessage());
            }
        }
    }

    // ==================== 更新 / 删除 / Kill ====================

    @PutMapping("/{serverId}")
    public ResponseEntity<Map<String, Object>> updateServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId, @RequestBody ServerInstances updates) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;
        if (updates == null) return badRequest("更新数据不能为空");

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        synchronized (processManager.getServerLock(serverId)) {
            boolean isRunning = Node.getRunningServers().containsKey(serverId);
            try {
                if (updates.getInstanceName() != null && !updates.getInstanceName().trim().isEmpty())
                    server.setInstanceName(updates.getInstanceName().trim());
                if (updates.getFilePath() != null && !updates.getFilePath().trim().isEmpty()) {
                    if (isRunning) return badRequest("无法修改运行中服务器的文件路径");
                    server.setFilePath(updates.getFilePath().trim());
                }
                if (updates.getVersion() != null && !updates.getVersion().trim().isEmpty())
                    server.setVersion(updates.getVersion().trim());
                if (updates.getCoreType() != null && !updates.getCoreType().trim().isEmpty())
                    server.setCoreType(updates.getCoreType().trim());
                if (updates.getPort() != null && updates.getPort() > 0 && updates.getPort() <= 65535)
                    server.setPort(updates.getPort());
                if (updates.getMemoryMb() != null && updates.getMemoryMb() > 0)
                    server.setMemoryMb(updates.getMemoryMb());
                if (updates.getJvmArgs() != null) server.setJvmArgs(updates.getJvmArgs().trim());

                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);

                logOperation(at.getMasterId(), OperationType.UPDATE_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));
                return ResponseEntity.ok(Map.of("success", true, "message", "服务器更新成功", "server", server));
            } catch (Exception e) {
                log.error("更新服务器时发生错误: {}", serverId, e);
                logOperation(at.getMasterId(), OperationType.UPDATE_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));
                return serverError("更新服务器失败: " + e.getMessage());
            }
        }
    }

    @PostMapping("/{serverId}/kill")
    public ResponseEntity<Map<String, Object>> killServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        synchronized (processManager.getServerLock(serverId)) {
            Process process = Node.getRunningServers().get(serverId);
            if (process == null) return badRequest("服务器未在运行");
            try {
                processManager.stopConsoleThread(serverId);
                process.destroyForcibly();
                boolean terminated = process.waitFor(10, TimeUnit.SECONDS);
                if (!terminated) {
                    log.warn("服务器 {} 的进程在10秒内未终止", serverId);
                }
                processManager.cleanupServer(serverId);
                queryManager.remove(serverId);
                updateServerStatus(serverId, "STOPPED");

                logOperation(at.getMasterId(), OperationType.KILL_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));
                return ResponseEntity.ok(Map.of("success", true, "message", "服务器强制终止成功"));
            } catch (Exception e) {
                log.error("强制终止服务器时发生错误: {}", serverId, e);
                logOperation(at.getMasterId(), OperationType.KILL_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));
                return serverError("强制终止服务器失败: " + e.getMessage());
            }
        }
    }

    @DeleteMapping("/{serverId}")
    public ResponseEntity<Map<String, Object>> deleteServer(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        synchronized (processManager.getServerLock(serverId)) {
            if (Node.getRunningServers().containsKey(serverId))
                return badRequest("无法删除正在运行的服务器");
            try {
                serverInstancesService.removeById(serverId);
                processManager.removeServerLock(serverId);
                consoleLogService.clearLogHistory(serverId);
                queryManager.remove(serverId);

                logOperation(at.getMasterId(), OperationType.DELETE_SERVER, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));
                return ResponseEntity.ok(Map.of("success", true, "message", "服务器删除成功"));
            } catch (Exception e) {
                log.error("删除服务器时发生错误: {}", serverId, e);
                logOperation(at.getMasterId(), OperationType.DELETE_SERVER, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));
                return serverError("删除服务器失败: " + e.getMessage());
            }
        }
    }

    // ==================== 控制台 ====================

    @GetMapping("/{serverId}/console")
    public ResponseEntity<Map<String, Object>> getConsole(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        Process process = Node.getRunningServers().get(serverId);
        if (process == null) return badRequest("服务器未在运行");

        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder output = new StringBuilder();
            String line;
            while (reader.ready() && (line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return ResponseEntity.ok(Map.of("console", output.toString(), "message", "建议使用 WebSocket 订阅实时控制台输出"));
        } catch (IOException e) {
            return serverError("读取控制台失败: " + e.getMessage());
        }
    }

    @GetMapping("/{serverId}/console/history")
    public ResponseEntity<Map<String, Object>> getConsoleHistory(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        List<String> logs = consoleLogService.getLogHistory(serverId);
        return ResponseEntity.ok(Map.of("success", true, "serverId", serverId, "logs", logs,
                "count", logs.size(), "maxLines", 2000));
    }

    @MessageMapping("/console/subscribe")
    public void subscribeConsole(@Payload Map<String, Object> request) {
        if (request == null) return;
        Integer serverId;
        String token;
        try {
            serverId = (Integer) request.get("serverId");
            token = (String) request.get("token");
        } catch (ClassCastException e) { return; }
        if (serverId == null || serverId <= 0) return;

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) {
            consoleLogService.dispatchToWebSocket(serverId, Map.of("error", "无效的访问令牌"));
            return;
        }
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null || !hasPermission(server, at)) {
            consoleLogService.dispatchToWebSocket(serverId, Map.of("error", server == null ? "未找到服务器" : "权限不足"));
            return;
        }
        Process process = Node.getRunningServers().get(serverId);
        if (process == null || !process.isAlive()) {
            consoleLogService.dispatchToWebSocket(serverId, Map.of("error", "服务器未在运行"));
            return;
        }
        consoleLogService.dispatchToWebSocket(serverId, Map.of("message", "已订阅控制台输出"));
    }

    // ==================== 命令 ====================

    @PostMapping("/{serverId}/command")
    public ResponseEntity<Map<String, Object>> sendCommand(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId, @RequestBody Map<String, String> request) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();
        if (request == null) return badRequest("请求体不能为空");

        String command = request.get("command");
        if (command == null || command.trim().isEmpty()) return badRequest("命令不能为空");
        try {
            command = CommandRestrictions.sanitizeMinecraftConsoleCommand(command, parseBlockedCommands());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        }

        synchronized (processManager.getServerLock(serverId)) {
            Process process = Node.getRunningServers().get(serverId);
            if (process == null) return badRequest("服务器未在运行");
            if (!process.isAlive()) {
                processManager.cleanupServer(serverId);
                return badRequest("服务器进程已终止");
            }
            try {
                processManager.sendCommand(serverId, process, command);
                log.info("向服务器 {} 发送命令: {}", serverId, command);
                logOperation(at.getMasterId(), OperationType.SEND_COMMAND, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "command", command));
                return ResponseEntity.ok(Map.of("success", true, "message", "命令发送成功"));
            } catch (Exception e) {
                log.error("向服务器发送命令时发生错误: {}, 命令: {}", serverId, command, e);
                logOperation(at.getMasterId(), OperationType.SEND_COMMAND, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "command", command, "error", e.getMessage()));
                return serverError("发送命令失败: " + e.getMessage());
            }
        }
    }

    // ==================== 状态 ====================

    @GetMapping("/{serverId}/status")
    public ResponseEntity<Map<String, Object>> getServerStatus(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        try {
            Process process = Node.getRunningServers().get(serverId);
            boolean isRunning = process != null && process.isAlive();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("serverId", serverId);
            response.put("instanceName", server.getInstanceName());
            response.put("status", server.getStatus());
            response.put("isRunning", isRunning);

            Map<String, Object> config = new HashMap<>();
            config.put("version", server.getVersion());
            config.put("coreType", server.getCoreType());
            config.put("port", server.getPort());
            config.put("memoryMb", server.getMemoryMb());
            config.put("jvmArgs", server.getJvmArgs());
            config.put("filePath", server.getFilePath());
            response.put("config", config);

            Map<String, Object> runtime = new HashMap<>();
            if (isRunning) {
                Long startTime = Node.getServerStartTimes().get(serverId);
                if (startTime != null) {
                    long seconds = (System.currentTimeMillis() - startTime) / 1000;
                    runtime.put("runtimeSeconds", seconds);
                    runtime.put("runtimeFormatted", formatRuntime(seconds));
                    runtime.put("startTime", new Date(startTime));
                }
            } else {
                runtime.put("runtimeSeconds", 0);
                runtime.put("runtimeFormatted", "0秒");
            }
            if (isRunning && process != null) {
                response.put("processInfo", processManager.getProcessInfo(process));
            }
            response.put("runtime", runtime);

            Map<String, Object> timestamps = new HashMap<>();
            if (server.getCreatedAt() != null) timestamps.put("createdAt", server.getCreatedAt());
            if (server.getUpdatedAt() != null) timestamps.put("updatedAt", server.getUpdatedAt());
            response.put("timestamps", timestamps);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("获取服务器状态时发生错误: {}", serverId, e);
            return serverError("获取服务器状态失败: " + e.getMessage());
        }
    }

    // ==================== 玩家 ====================

    @GetMapping("/{serverId}/players")
    public ResponseEntity<Map<String, Object>> getOnlinePlayers(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        Process process = Node.getRunningServers().get(serverId);
        if (process == null || !process.isAlive()) return badRequest("服务器未在运行");

        try {
            QueryConnectionManager.QueryResult qr = queryManager.queryPlayers(serverId, server);
            if (qr != null && qr.success()) {
                Map<String, Object> response = queryManager.buildPlayerResponse(
                        serverId, server, qr.status(), qr.host(), qr.port(), qr.method());
                logOperation(at.getMasterId(), OperationType.GET_PLAYERS, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "method", qr.method()));
                return ResponseEntity.ok(response);
            }

            // Query 失败，返回诊断信息
            int gamePort = server.getPort() != null ? server.getPort() : 25565;
            int queryPort = queryManager.getOrAssignQueryPort(server);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("error", "无法获取玩家信息");
            response.put("players", new ArrayList<>());
            response.put("playerCount", Map.of("online", 0, "max", 0));
            response.put("troubleshooting", Map.of("queryPort", queryPort, "gamePort", gamePort, "suggestions", List.of(
                    "检查server.properties中enable-query=true", "确认query.port=" + queryPort,
                    "检查防火墙是否开放Query端口", "确认服务器版本支持Query协议", "等待服务器完全启动后再试")));
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("获取服务器 {} 在线玩家信息时发生错误", serverId, e);
            return ResponseEntity.status(500).body(Map.of("success", false, "error", "获取玩家信息失败: " + e.getMessage(),
                    "players", new ArrayList<>(), "playerCount", Map.of("online", 0, "max", 0)));
        }
    }

    @GetMapping("/{serverId}/query-diagnostic")
    public ResponseEntity<Map<String, Object>> queryDiagnostic(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        Map<String, Object> diag = new HashMap<>();
        try {
            int gamePort = queryManager.getServerPort(server);
            int queryPort = queryManager.getOrAssignQueryPort(server);
            diag.put("serverId", serverId);
            diag.put("gamePort", gamePort);
            diag.put("queryPort", queryPort);
            diag.put("serverRunning", Node.getRunningServers().containsKey(serverId));

            File propsFile = new File(server.getFilePath(), "server.properties");
            Map<String, Object> propsInfo = new HashMap<>();
            propsInfo.put("exists", propsFile.exists());
            if (propsFile.exists()) {
                try {
                    Properties props = new Properties();
                    try (FileInputStream fis = new FileInputStream(propsFile)) { props.load(fis); }
                    propsInfo.put("enable-query", props.getProperty("enable-query"));
                    propsInfo.put("query.port", props.getProperty("query.port"));
                    propsInfo.put("server-port", props.getProperty("server-port"));
                } catch (Exception e) { propsInfo.put("readError", e.getMessage()); }
            }
            diag.put("serverProperties", propsInfo);
            diag.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.ok(diag);
        } catch (Exception e) {
            log.error("Query诊断失败", e);
            diag.put("error", "诊断失败: " + e.getMessage());
            return ResponseEntity.status(500).body(diag);
        }
    }

    // ==================== 备份管理 ====================

    @GetMapping("/{serverId}/backup/list")
    public ResponseEntity<Map<String, Object>> listBackups(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        List<BackupService.BackupInfo> backups = backupService.listBackups(serverId);
        List<Map<String, Object>> list = new ArrayList<>();
        for (BackupService.BackupInfo b : backups) {
            list.add(Map.of(
                    "fileName", b.fileName(),
                    "timestamp", b.timestamp(),
                    "sizeBytes", b.sizeBytes(),
                    "sizeFormatted", b.sizeFormatted(),
                    "lastModified", new Date(b.lastModified())
            ));
        }
        return ResponseEntity.ok(Map.of("success", true, "serverId", serverId, "backups", list, "count", list.size()));
    }

    @PostMapping("/{serverId}/backup/restore")
    public ResponseEntity<Map<String, Object>> restoreBackup(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId,
            @RequestBody Map<String, String> request) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;

        if (request == null || !request.containsKey("fileName")) {
            return badRequest("请指定要恢复的备份文件名");
        }
        String fileName = request.get("fileName");

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        // 运行中的服务器不允许恢复
        if (Node.getRunningServers().containsKey(serverId)) {
            return badRequest("无法恢复运行中的服务器，请先停止服务器");
        }

        BackupService.RestoreResult result = backupService.restoreBackup(serverId, fileName, server.getFilePath());
        if (result.success()) {
            logOperation(at.getMasterId(), OperationType.RESTORE_BACKUP, true,
                    Map.of("instanceId", serverId, "fileName", fileName));
            return ResponseEntity.ok(Map.of("success", true, "message", result.message()));
        } else {
            return serverError(result.message());
        }
    }

    // ==================== 白名单 / Ops 管理 ====================

    @GetMapping("/{serverId}/whitelist")
    public ResponseEntity<Map<String, Object>> getWhitelist(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {
        return readJsonFile(token, serverId, "whitelist.json");
    }

    @PostMapping("/{serverId}/whitelist")
    public ResponseEntity<Map<String, Object>> addToWhitelist(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId, @RequestBody Map<String, String> request) {
        return addToList(token, serverId, "whitelist.json", request, "whitelist add");
    }

    @DeleteMapping("/{serverId}/whitelist/{playerName}")
    public ResponseEntity<Map<String, Object>> removeFromWhitelist(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId, @PathVariable String playerName) {
        return removeFromList(token, serverId, "whitelist.json", playerName, "whitelist remove");
    }

    @GetMapping("/{serverId}/ops")
    public ResponseEntity<Map<String, Object>> getOps(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token, @PathVariable Integer serverId) {
        return readJsonFile(token, serverId, "ops.json");
    }

    @PostMapping("/{serverId}/ops")
    public ResponseEntity<Map<String, Object>> addOp(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId, @RequestBody Map<String, String> request) {
        return addToList(token, serverId, "ops.json", request, "op");
    }

    @DeleteMapping("/{serverId}/ops/{playerName}")
    public ResponseEntity<Map<String, Object>> removeOp(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId, @PathVariable String playerName) {
        return removeFromList(token, serverId, "ops.json", playerName, "deop");
    }

    private ResponseEntity<Map<String, Object>> readJsonFile(String token, Integer serverId, String fileName) {
        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        java.io.File file = new java.io.File(server.getFilePath(), fileName);
        if (!file.exists()) return ResponseEntity.ok(Map.of("success", true, "data", List.of()));
        try {
            String content = java.nio.file.Files.readString(file.toPath());
            return ResponseEntity.ok(Map.of("success", true, "data", content));
        } catch (Exception e) {
            return serverError("读取 " + fileName + " 失败: " + e.getMessage());
        }
    }

    private ResponseEntity<Map<String, Object>> addToList(String token, Integer serverId, String fileName,
                                                           Map<String, String> request, String commandPrefix) {
        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();
        String playerName = request.get("name");
        if (playerName == null || playerName.trim().isEmpty()) return badRequest("玩家名称不能为空");

        // 通过控制台命令添加（MC 会自动更新 JSON 文件）
        Process process = Node.getRunningServers().get(serverId);
        if (process != null && process.isAlive()) {
            try {
                processManager.sendCommand(serverId, process, commandPrefix + " " + playerName);
            } catch (Exception e) {
                return serverError("发送命令失败: " + e.getMessage());
            }
        }
        return ResponseEntity.ok(Map.of("success", true, "message", "已发送 " + commandPrefix + " 命令"));
    }

    private ResponseEntity<Map<String, Object>> removeFromList(String token, Integer serverId, String fileName,
                                                                String playerName, String commandPrefix) {
        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        Process process = Node.getRunningServers().get(serverId);
        if (process != null && process.isAlive()) {
            try {
                processManager.sendCommand(serverId, process, commandPrefix + " " + playerName);
            } catch (Exception e) {
                return serverError("发送命令失败: " + e.getMessage());
            }
        }
        return ResponseEntity.ok(Map.of("success", true, "message", "已发送 " + commandPrefix + " 命令"));
    }

    @PostMapping("/{serverId}/players/{playerName}/action")
    public ResponseEntity<Map<String, Object>> playerAction(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @PathVariable Integer serverId, @PathVariable String playerName,
            @RequestBody Map<String, String> request) {

        AccessTokens at = getAuthenticatedToken(token);
        if (at == null) return unauthorized();
        ResponseEntity<Map<String, Object>> idErr = validateServerId(serverId);
        if (idErr != null) return idErr;
        if (playerName == null || playerName.trim().isEmpty()) return badRequest("玩家名称不能为空");
        if (request == null || !request.containsKey("action")) return badRequest("操作类型不能为空");

        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) return ResponseEntity.notFound().build();
        if (!hasPermission(server, at)) return forbidden();

        Process process = Node.getRunningServers().get(serverId);
        if (process == null || !process.isAlive()) return badRequest("服务器未在运行");

        String action = request.get("action");
        String reason = request.getOrDefault("reason", "");
        String command = buildPlayerCommand(action, playerName, reason);
        if (command == null) return badRequest("不支持的操作类型: " + action);

        synchronized (processManager.getServerLock(serverId)) {
            try {
                processManager.sendCommand(serverId, process, command);
                log.info("对玩家 {} 执行操作: {} (服务器: {})", playerName, action, serverId);
                logOperation(at.getMasterId(), OperationType.PLAYER_ACTION, true,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                "action", action, "player", playerName, "command", command));
                return ResponseEntity.ok(Map.of("success", true, "message", "操作执行成功",
                        "action", action, "player", playerName, "command", command));
            } catch (Exception e) {
                log.error("对玩家 {} 执行操作 {} 时发生错误 (服务器: {})", playerName, action, serverId, e);
                logOperation(at.getMasterId(), OperationType.PLAYER_ACTION, false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                "action", action, "player", playerName, "error", e.getMessage()));
                return serverError("操作执行失败: " + e.getMessage());
            }
        }
    }

    // ==================== 内部辅助方法 ====================

    /**
     * 获取当前已认证的 AccessTokens 对象。
     * 优先从 SecurityContextHolder 读取（SecurityConfig filter 已完成 DB 查询和缓存），
     * 仅在 SecurityContext 无认证信息时回退到 DB 查询。
     */
    private AccessTokens getAuthenticatedToken(String token) {
        if (token == null || token.trim().isEmpty()) return null;

        // 优先从 SecurityContext 获取（filter 已做校验 + 缓存）
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getDetails() instanceof AccessTokens at) {
            return at;
        }

        // 回退：DB 查询（理论上不应走到这里，除非请求路径未经 SecurityConfig filter）
        try {
            return accessTokensService.lambdaQuery().eq(AccessTokens::getToken, token).one();
        } catch (Exception e) {
            log.error("验证令牌时发生错误", e);
            return null;
        }
    }

    private boolean hasPermission(ServerInstances server, AccessTokens at) {
        return server != null && at != null && server.getCreatedBy() != null
                && server.getCreatedBy().equals(at.getMasterUuid());
    }

    private void logOperation(Integer masterId, String type, boolean success, Map<String, Object> detail) {
        if (masterId == null || type == null) return;
        try {
            AsyncManager.me().execute(new TimerTask() {
                @Override public void run() {
                    try {
                        OperationLogs opLog = new OperationLogs();
                        opLog.setMasterId(masterId);
                        opLog.setOperationType(type);
                        opLog.setOperationTime(new Date());
                        opLog.setIsSuccess(success ? 1 : 0);
                        opLog.setDetail(detail != null ? detail.toString() : "");
                        operationLogsService.save(opLog);
                    } catch (Exception e) {
                        log.error("保存操作日志失败", e);
                    }
                }
            });
        } catch (Exception e) {
            log.error("调度操作日志任务失败", e);
        }
    }

    private void updateServerStatus(Integer serverId, String status) {
        try {
            ServerInstances s = serverInstancesService.getById(serverId);
            if (s != null) {
                s.setStatus(status);
                s.setUpdatedAt(new Date());
                serverInstancesService.updateById(s);
            }
        } catch (Exception e) {
            log.error("更新服务器 {} 状态失败", serverId, e);
        }
    }

    private String extractScript(Map<String, String> body) {
        if (body == null) return null;
        String s = body.get("script");
        return (s != null && !s.trim().isEmpty()) ? s : null;
    }

    private Set<String> parseBlockedCommands() {
        if (blockedMcCommands == null || blockedMcCommands.trim().isEmpty()) return Set.of();
        Set<String> set = new HashSet<>();
        for (String part : blockedMcCommands.split(",")) {
            String s = part == null ? "" : part.trim().toLowerCase(java.util.Locale.ROOT);
            if (!s.isEmpty()) set.add(s);
        }
        return set;
    }

    private String buildPlayerCommand(String action, String playerName, String reason) {
        return switch (action.toLowerCase()) {
            case "kick" -> reason.isEmpty() ? "kick " + playerName : "kick " + playerName + " " + reason;
            case "ban" -> reason.isEmpty() ? "ban " + playerName : "ban " + playerName + " " + reason;
            case "ban-ip" -> reason.isEmpty() ? "ban-ip " + playerName : "ban-ip " + playerName + " " + reason;
            case "pardon" -> "pardon " + playerName;
            case "pardon-ip" -> "pardon-ip " + playerName;
            case "op" -> "op " + playerName;
            case "deop" -> "deop " + playerName;
            case "whitelist-add" -> "whitelist add " + playerName;
            case "whitelist-remove" -> "whitelist remove " + playerName;
            case "gamemode-creative" -> "gamemode creative " + playerName;
            case "gamemode-survival" -> "gamemode survival " + playerName;
            case "gamemode-adventure" -> "gamemode adventure " + playerName;
            case "gamemode-spectator" -> "gamemode spectator " + playerName;
            case "tp-to-spawn" -> "tp " + playerName + " ~ ~ ~";
            default -> null;
        };
    }

    private String formatRuntime(long seconds) {
        if (seconds < 0) return "0秒";
        long d = seconds / 86400, h = (seconds % 86400) / 3600, m = (seconds % 3600) / 60, s = seconds % 60;
        StringBuilder sb = new StringBuilder();
        if (d > 0) sb.append(d).append("天 ");
        if (h > 0) sb.append(h).append("小时 ");
        if (m > 0) sb.append(m).append("分钟 ");
        if (s > 0 || sb.length() == 0) sb.append(s).append("秒");
        return sb.toString().trim();
    }

    private ResponseEntity<Map<String, Object>> validateServerId(Integer serverId) {
        if (serverId == null || serverId <= 0) return badRequest("无效的服务器ID");
        return null;
    }

    private ResponseEntity<Map<String, Object>> unauthorized() {
        return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
    }

    private ResponseEntity<Map<String, Object>> forbidden() {
        return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
    }

    private ResponseEntity<Map<String, Object>> badRequest(String msg) {
        return ResponseEntity.badRequest().body(Map.of("error", msg));
    }

    private ResponseEntity<Map<String, Object>> serverError(String msg) {
        return ResponseEntity.status(500).body(Map.of("error", msg));
    }

    /**
     * 自动分配可用端口：扫描 25565-25665 范围，找到未被占用且未被该用户其他实例使用的端口
     */
    private int findAvailablePort(String masterUuid) {
        Set<Integer> usedPorts = new HashSet<>();
        serverInstancesService.lambdaQuery()
                .eq(ServerInstances::getCreatedBy, masterUuid)
                .select(ServerInstances::getPort)
                .list()
                .forEach(inst -> { if (inst.getPort() != null) usedPorts.add(inst.getPort()); });

        for (int port = 25565; port <= 25665; port++) {
            if (usedPorts.contains(port)) continue;
            if (processManager.isPortAvailable(port)) return port;
        }
        return -1;
    }
}
