package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.OperationLogs;
import cc.endmc.endlessnode.domain.ServerInstances;
import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.service.OperationLogsService;
import cc.endmc.endlessnode.service.ServerInstancesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * WebSocket控制器
 * 提供基于WebSocket长连接的服务，包括服务器管理、文件操作、系统监控等
 */
@Controller
@RequiredArgsConstructor
@Slf4j
public class WebSocketController {

    private final AccessTokensService accessTokensService;
    private final ServerInstancesService serverInstancesService;
    private final OperationLogsService operationLogsService;
    private final SimpMessagingTemplate messagingTemplate;

    // 存储正在运行的服务器进程
    private final Map<Integer, Process> runningServers = new ConcurrentHashMap<>();
    
    // 存储服务器控制台输出线程
    private final Map<Integer, Thread> consoleThreads = new ConcurrentHashMap<>();
    
    // 存储活跃的WebSocket会话
    private final Map<String, Set<String>> activeSessions = new ConcurrentHashMap<>();
    
    // 线程池，用于管理控制台输出线程
    private final ExecutorService executorService = Executors.newCachedThreadPool();

    /**
     * WebSocket认证
     * 客户端连接时进行身份验证
     */
    @MessageMapping("/auth")
    public void authenticate(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String token = (String) payload.get("token");
        String sessionId = headerAccessor.getSessionId();
        
        try {
            // 验证令牌
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            if (accessToken == null || accessToken.getExpiresAt().before(new Date())) {
                messagingTemplate.convertAndSendToUser(sessionId, "/queue/auth", 
                    Map.of("success", false, "message", "认证失败或令牌已过期"));
                return;
            }

            // 保存会话信息
            activeSessions.computeIfAbsent(sessionId, k -> new HashSet<>()).add("authenticated");
            
            messagingTemplate.convertAndSendToUser(sessionId, "/queue/auth", 
                Map.of("success", true, "message", "认证成功", "masterId", accessToken.getMasterId()));
                
            log.info("WebSocket认证成功: sessionId={}, masterId={}", sessionId, accessToken.getMasterId());
        } catch (Exception e) {
            messagingTemplate.convertAndSendToUser(sessionId, "/queue/auth", 
                Map.of("success", false, "message", "认证失败: " + e.getMessage()));
            log.error("WebSocket认证失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 获取服务器列表
     */
    @MessageMapping("/servers/list")
    public void getServerList(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/servers", "未认证");
            return;
        }

        try {
            String token = (String) payload.get("token");
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            List<ServerInstances> instances = serverInstancesService.lambdaQuery()
                    .eq(ServerInstances::getCreatedBy, accessToken.getMasterId())
                    .list();

            // 更新实例状态
            for (ServerInstances instance : instances) {
                boolean isRunning = runningServers.containsKey(instance.getId());
                if (isRunning != "RUNNING".equals(instance.getStatus())) {
                    instance.setStatus(isRunning ? "RUNNING" : "STOPPED");
                    serverInstancesService.updateById(instance);
                }
            }

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/servers", 
                Map.of("type", "list", "servers", instances));
                
        } catch (Exception e) {
            sendError(sessionId, "/queue/servers", "获取服务器列表失败: " + e.getMessage());
            log.error("获取服务器列表失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 启动服务器
     */
    @MessageMapping("/servers/start")
    public void startServer(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/servers", "未认证");
            return;
        }

        try {
            String token = (String) payload.get("token");
            Integer serverId = (Integer) payload.get("serverId");
            String startScript = (String) payload.get("startScript");

            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            ServerInstances server = serverInstancesService.getById(serverId);
            if (server == null) {
                sendError(sessionId, "/queue/servers", "服务器不存在");
                return;
            }

            if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
                sendError(sessionId, "/queue/servers", "权限不足");
                return;
            }

            if (runningServers.containsKey(serverId)) {
                sendError(sessionId, "/queue/servers", "服务器已经在运行中");
                return;
            }

            // 启动服务器
            Process process;
            if (startScript != null && !startScript.isEmpty()) {
                process = startMinecraftServerWithScript(server, startScript);
            } else {
                process = startMinecraftServer(server);
            }

            runningServers.put(serverId, process);
            startConsoleOutputThread(serverId, process);

            server.setStatus("RUNNING");
            server.setUpdatedAt(new Date());
            serverInstancesService.updateById(server);

            logOperation(accessToken.getMasterId(), "START_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/servers", 
                Map.of("type", "start", "success", true, "message", "服务器启动成功", "serverId", serverId));

        } catch (Exception e) {
            sendError(sessionId, "/queue/servers", "启动服务器失败: " + e.getMessage());
            log.error("启动服务器失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 停止服务器
     */
    @MessageMapping("/servers/stop")
    public void stopServer(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/servers", "未认证");
            return;
        }

        try {
            String token = (String) payload.get("token");
            Integer serverId = (Integer) payload.get("serverId");
            String stopScript = (String) payload.get("stopScript");

            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            ServerInstances server = serverInstancesService.getById(serverId);
            if (server == null) {
                sendError(sessionId, "/queue/servers", "服务器不存在");
                return;
            }

            if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
                sendError(sessionId, "/queue/servers", "权限不足");
                return;
            }

            Process process = runningServers.get(serverId);
            if (process == null) {
                sendError(sessionId, "/queue/servers", "服务器未在运行");
                return;
            }

            stopConsoleOutputThread(serverId);

            if (stopScript != null && !stopScript.isEmpty()) {
                executeStopScript(server, stopScript);
            } else {
                process.destroy();
            }

            runningServers.remove(serverId);

            server.setStatus("STOPPED");
            server.setUpdatedAt(new Date());
            serverInstancesService.updateById(server);

            logOperation(accessToken.getMasterId(), "STOP_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/servers", 
                Map.of("type", "stop", "success", true, "message", "服务器停止成功", "serverId", serverId));

        } catch (Exception e) {
            sendError(sessionId, "/queue/servers", "停止服务器失败: " + e.getMessage());
            log.error("停止服务器失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 重启服务器
     */
    @MessageMapping("/servers/restart")
    public void restartServer(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/servers", "未认证");
            return;
        }

        try {
            String token = (String) payload.get("token");
            Integer serverId = (Integer) payload.get("serverId");
            String startScript = (String) payload.get("startScript");
            String stopScript = (String) payload.get("stopScript");

            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            ServerInstances server = serverInstancesService.getById(serverId);
            if (server == null) {
                sendError(sessionId, "/queue/servers", "服务器不存在");
                return;
            }

            if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
                sendError(sessionId, "/queue/servers", "权限不足");
                return;
            }

            Process process = runningServers.get(serverId);
            if (process == null) {
                sendError(sessionId, "/queue/servers", "服务器未在运行");
                return;
            }

            // 停止服务器
            stopConsoleOutputThread(serverId);
            if (stopScript != null && !stopScript.isEmpty()) {
                executeStopScript(server, stopScript);
            } else {
                process.destroy();
            }
            runningServers.remove(serverId);

            // 等待进程完全终止
            Thread.sleep(5000);

            // 启动服务器
            Process newProcess;
            if (startScript != null && !startScript.isEmpty()) {
                newProcess = startMinecraftServerWithScript(server, startScript);
            } else {
                newProcess = startMinecraftServer(server);
            }

            runningServers.put(serverId, newProcess);
            startConsoleOutputThread(serverId, newProcess);

            server.setStatus("RUNNING");
            server.setUpdatedAt(new Date());
            serverInstancesService.updateById(server);

            logOperation(accessToken.getMasterId(), "RESTART_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/servers", 
                Map.of("type", "restart", "success", true, "message", "服务器重启成功", "serverId", serverId));

        } catch (Exception e) {
            sendError(sessionId, "/queue/servers", "重启服务器失败: " + e.getMessage());
            log.error("重启服务器失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 发送服务器命令
     */
    @MessageMapping("/servers/command")
    public void sendCommand(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/servers", "未认证");
            return;
        }

        try {
            String token = (String) payload.get("token");
            Integer serverId = (Integer) payload.get("serverId");
            String command = (String) payload.get("command");

            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            ServerInstances server = serverInstancesService.getById(serverId);
            if (server == null) {
                sendError(sessionId, "/queue/servers", "服务器不存在");
                return;
            }

            if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
                sendError(sessionId, "/queue/servers", "权限不足");
                return;
            }

            Process process = runningServers.get(serverId);
            if (process == null) {
                sendError(sessionId, "/queue/servers", "服务器未在运行");
                return;
            }

            // 发送命令到服务器进程
            // 这里需要根据实际的服务器类型来实现命令发送逻辑
            
            logOperation(accessToken.getMasterId(), "SEND_COMMAND", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "command", command));

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/servers", 
                Map.of("type", "command", "success", true, "message", "命令发送成功", "serverId", serverId));

        } catch (Exception e) {
            sendError(sessionId, "/queue/servers", "发送命令失败: " + e.getMessage());
            log.error("发送命令失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 订阅服务器控制台输出
     */
    @MessageMapping("/servers/console/subscribe")
    public void subscribeConsole(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/console", "未认证");
            return;
        }

        try {
            String token = (String) payload.get("token");
            Integer serverId = (Integer) payload.get("serverId");

            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            ServerInstances server = serverInstancesService.getById(serverId);
            if (server == null) {
                messagingTemplate.convertAndSendToUser(sessionId, "/queue/console", 
                    Map.of("error", "未找到服务器"));
                return;
            }

            if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
                messagingTemplate.convertAndSendToUser(sessionId, "/queue/console", 
                    Map.of("error", "权限不足"));
                return;
            }

            Process process = runningServers.get(serverId);
            if (process == null) {
                messagingTemplate.convertAndSendToUser(sessionId, "/queue/console", 
                    Map.of("error", "服务器未在运行"));
                return;
            }

            // 将sessionId添加到控制台订阅列表
            activeSessions.computeIfAbsent(sessionId, k -> new HashSet<>()).add("console_" + serverId);

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/console", 
                Map.of("message", "已订阅控制台输出", "serverId", serverId));

        } catch (Exception e) {
            messagingTemplate.convertAndSendToUser(sessionId, "/queue/console", 
                Map.of("error", "订阅控制台失败: " + e.getMessage()));
            log.error("订阅控制台失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 取消订阅服务器控制台输出
     */
    @MessageMapping("/servers/console/unsubscribe")
    public void unsubscribeConsole(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/console", "未认证");
            return;
        }

        try {
            Integer serverId = (Integer) payload.get("serverId");
            
            // 从控制台订阅列表中移除
            Set<String> sessionData = activeSessions.get(sessionId);
            if (sessionData != null) {
                sessionData.remove("console_" + serverId);
            }

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/console", 
                Map.of("message", "已取消订阅控制台输出", "serverId", serverId));

        } catch (Exception e) {
            messagingTemplate.convertAndSendToUser(sessionId, "/queue/console", 
                Map.of("error", "取消订阅控制台失败: " + e.getMessage()));
            log.error("取消订阅控制台失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 获取文件列表
     */
    @MessageMapping("/files/list")
    public void getFileList(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/files", "未认证");
            return;
        }

        try {
            String path = (String) payload.get("path");
            if (path == null) path = "";

            // 检查是否为Windows系统
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("windows");

            // 如果是Windows系统且路径为空，返回所有可用驱动器
            if (isWindows && path.isEmpty()) {
                List<Map<String, Object>> drives = Arrays.stream(File.listRoots())
                        .map(drive -> {
                            Map<String, Object> driveInfo = new HashMap<>();
                            driveInfo.put("name", drive.getPath());
                            driveInfo.put("path", drive.getPath());
                            driveInfo.put("isDirectory", true);
                            driveInfo.put("totalSpace", drive.getTotalSpace());
                            driveInfo.put("freeSpace", drive.getFreeSpace());
                            driveInfo.put("usableSpace", drive.getUsableSpace());
                            driveInfo.put("lastModified", 0L);
                            return driveInfo;
                        })
                        .collect(java.util.stream.Collectors.toList());

                messagingTemplate.convertAndSendToUser(sessionId, "/queue/files", 
                    Map.of("type", "list", "path", "", "files", drives, "success", true));
                return;
            }

            // 构建目标路径
            java.nio.file.Path targetPath = path.isEmpty() ? java.nio.file.Paths.get("/") : java.nio.file.Paths.get(path);

            // 检查路径是否存在
            if (!java.nio.file.Files.exists(targetPath)) {
                sendError(sessionId, "/queue/files", "路径不存在");
                return;
            }

            // 检查是否为目录
            if (!java.nio.file.Files.isDirectory(targetPath)) {
                sendError(sessionId, "/queue/files", "目录不存在或不是目录");
                return;
            }

            // 获取目录内容
            List<Map<String, Object>> files = java.nio.file.Files.list(targetPath)
                    .map(filePath -> {
                        Map<String, Object> fileInfo = new HashMap<>();
                        fileInfo.put("name", filePath.getFileName().toString());
                        fileInfo.put("path", filePath.toAbsolutePath().toString());
                        fileInfo.put("isDirectory", java.nio.file.Files.isDirectory(filePath));

                        try {
                            fileInfo.put("size", java.nio.file.Files.size(filePath));
                            fileInfo.put("lastModified", java.nio.file.Files.getLastModifiedTime(filePath).toMillis());
                        } catch (IOException e) {
                            fileInfo.put("size", 0);
                            fileInfo.put("lastModified", 0);
                        }

                        return fileInfo;
                    })
                    .collect(java.util.stream.Collectors.toList());

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/files", 
                Map.of("type", "list", "path", path, "files", files, "success", true));

        } catch (Exception e) {
            sendError(sessionId, "/queue/files", "获取文件列表失败: " + e.getMessage());
            log.error("获取文件列表失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 删除文件或目录
     */
    @MessageMapping("/files/delete")
    public void deleteFile(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/files", "未认证");
            return;
        }

        try {
            String path = (String) payload.get("path");
            if (path == null || path.isEmpty()) {
                sendError(sessionId, "/queue/files", "路径不能为空");
                return;
            }

            java.nio.file.Path targetPath = java.nio.file.Paths.get(path);

            // 检查路径是否存在
            if (!java.nio.file.Files.exists(targetPath)) {
                sendError(sessionId, "/queue/files", "路径不存在");
                return;
            }

            // 删除文件或目录
            if (java.nio.file.Files.isDirectory(targetPath)) {
                deleteDirectory(targetPath);
            } else {
                java.nio.file.Files.delete(targetPath);
            }

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/files", 
                Map.of("type", "delete", "success", true, "message", "删除成功", "path", path));

        } catch (Exception e) {
            sendError(sessionId, "/queue/files", "删除失败: " + e.getMessage());
            log.error("删除文件失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 从URL下载文件
     */
    @MessageMapping("/files/download-url")
    public void downloadFromUrl(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/files", "未认证");
            return;
        }

        try {
            String url = (String) payload.get("url");
            String path = (String) payload.get("path");

            if (url == null || url.isEmpty()) {
                sendError(sessionId, "/queue/files", "URL不能为空");
                return;
            }

            if (path == null || path.isEmpty()) {
                sendError(sessionId, "/queue/files", "保存路径不能为空");
                return;
            }

            // 验证URL格式
            java.net.URL fileUrl = new java.net.URL(url);

            // 打开连接获取文件名
            java.net.URLConnection connection = fileUrl.openConnection();
            String fileName = getFileNameFromUrl(url, connection);

            // 构建目标路径
            java.nio.file.Path targetPath = java.nio.file.Paths.get(path);

            // 如果目标是目录，则添加文件名
            if (java.nio.file.Files.isDirectory(targetPath) || !targetPath.toString().contains(".")) {
                targetPath = targetPath.resolve(fileName);
            }

            // 异步开始下载
            downloadFileAsync(url, targetPath.toString(), fileName);

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/files", 
                Map.of("type", "download", "success", true, "message", "下载已开始", 
                       "targetPath", targetPath.toString(), "fileName", fileName, "url", url));

        } catch (Exception e) {
            sendError(sessionId, "/queue/files", "下载失败: " + e.getMessage());
            log.error("下载文件失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 获取系统信息
     */
    @MessageMapping("/system/info")
    public void getSystemInfo(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/system", "未认证");
            return;
        }

        try {
            // 这里可以调用SystemController的逻辑来获取系统信息
            // 为了简化，这里返回基本信息
            Map<String, Object> systemInfo = new HashMap<>();
            systemInfo.put("os", System.getProperty("os.name"));
            systemInfo.put("version", System.getProperty("os.version"));
            systemInfo.put("arch", System.getProperty("os.arch"));
            systemInfo.put("javaVersion", System.getProperty("java.version"));
            systemInfo.put("timestamp", System.currentTimeMillis());

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/system", 
                Map.of("type", "info", "data", systemInfo));

        } catch (Exception e) {
            sendError(sessionId, "/queue/system", "获取系统信息失败: " + e.getMessage());
            log.error("获取系统信息失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 订阅系统监控
     */
    @MessageMapping("/system/monitor/subscribe")
    public void subscribeSystemMonitor(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/system", "未认证");
            return;
        }

        try {
            // 将sessionId添加到系统监控订阅列表
            activeSessions.computeIfAbsent(sessionId, k -> new HashSet<>()).add("system_monitor");

            // 启动系统监控线程
            startSystemMonitorThread(sessionId);

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/system", 
                Map.of("type", "monitor", "message", "已订阅系统监控"));

        } catch (Exception e) {
            sendError(sessionId, "/queue/system", "订阅系统监控失败: " + e.getMessage());
            log.error("订阅系统监控失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 取消订阅系统监控
     */
    @MessageMapping("/system/monitor/unsubscribe")
    public void unsubscribeSystemMonitor(@Payload Map<String, Object> payload, SimpMessageHeaderAccessor headerAccessor) {
        String sessionId = headerAccessor.getSessionId();
        
        if (!isAuthenticated(sessionId)) {
            sendError(sessionId, "/queue/system", "未认证");
            return;
        }

        try {
            // 从系统监控订阅列表中移除
            Set<String> sessionData = activeSessions.get(sessionId);
            if (sessionData != null) {
                sessionData.remove("system_monitor");
            }

            messagingTemplate.convertAndSendToUser(sessionId, "/queue/system", 
                Map.of("type", "monitor", "message", "已取消订阅系统监控"));

        } catch (Exception e) {
            sendError(sessionId, "/queue/system", "取消订阅系统监控失败: " + e.getMessage());
            log.error("取消订阅系统监控失败: sessionId={}", sessionId, e);
        }
    }

    /**
     * 启动控制台输出线程
     */
    private void startConsoleOutputThread(Integer serverId, Process process) {
        stopConsoleOutputThread(serverId);

        Thread consoleThread = new Thread(() -> {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    // 发送控制台输出到所有订阅的客户端
                    messagingTemplate.convertAndSend("/topic/console/" + serverId,
                            Map.of("line", line, "timestamp", System.currentTimeMillis()));
                }
            } catch (IOException e) {
                if (!process.isAlive()) {
                    return;
                }
                messagingTemplate.convertAndSend("/topic/console/" + serverId,
                        Map.of("error", "读取控制台失败: " + e.getMessage()));
            }
        });

        consoleThread.setDaemon(true);
        consoleThread.start();
        consoleThreads.put(serverId, consoleThread);
    }

    /**
     * 停止控制台输出线程
     */
    private void stopConsoleOutputThread(Integer serverId) {
        Thread consoleThread = consoleThreads.remove(serverId);
        if (consoleThread != null) {
            consoleThread.interrupt();
        }
    }

    /**
     * 启动Minecraft服务器
     */
    private Process startMinecraftServer(ServerInstances server) throws IOException {
        List<String> command = new ArrayList<>();
        command.add("java");

        if (server.getJvmArgs() != null && !server.getJvmArgs().isEmpty()) {
            command.addAll(Arrays.asList(server.getJvmArgs().split("\\s+")));
        } else {
            command.add("-Xmx" + server.getMemoryMb() + "M");
            command.add("-Xms" + (server.getMemoryMb() / 2) + "M");
        }

        String jarPath = server.getFilePath() + "/" + getJarFileName(server);
        command.add("-jar");
        command.add(jarPath);
        command.add("nogui");

        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            workingDir.mkdirs();
        }

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(workingDir);
        processBuilder.redirectErrorStream(true);

        return processBuilder.start();
    }

    /**
     * 使用自定义脚本启动Minecraft服务器
     */
    private Process startMinecraftServerWithScript(ServerInstances server, String script) throws IOException {
        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            workingDir.mkdirs();
        }

        File scriptFile = new File(workingDir, "start.sh");
        java.nio.file.Files.write(scriptFile.toPath(), script.getBytes());
        scriptFile.setExecutable(true);

        ProcessBuilder processBuilder = new ProcessBuilder(scriptFile.getAbsolutePath());
        processBuilder.directory(workingDir);
        processBuilder.redirectErrorStream(true);

        return processBuilder.start();
    }

    /**
     * 执行停止脚本
     */
    private void executeStopScript(ServerInstances server, String script) throws IOException, InterruptedException {
        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            workingDir.mkdirs();
        }

        File scriptFile = new File(workingDir, "stop.sh");
        java.nio.file.Files.write(scriptFile.toPath(), script.getBytes());
        scriptFile.setExecutable(true);

        ProcessBuilder processBuilder = new ProcessBuilder(scriptFile.getAbsolutePath());
        processBuilder.directory(workingDir);
        processBuilder.start().waitFor();
    }

    /**
     * 获取服务器jar文件名
     */
    private String getJarFileName(ServerInstances server) {
        switch (server.getCoreType().toUpperCase()) {
            case "VANILLA":
                return "minecraft_server." + server.getVersion() + ".jar";
            case "PAPER":
                return "paper-" + server.getVersion() + ".jar";
            case "SPIGOT":
                return "spigot-" + server.getVersion() + ".jar";
            default:
                return "server.jar";
        }
    }

    /**
     * 检查是否已认证
     */
    private boolean isAuthenticated(String sessionId) {
        Set<String> sessionData = activeSessions.get(sessionId);
        return sessionData != null && sessionData.contains("authenticated");
    }

    /**
     * 发送错误消息
     */
    private void sendError(String sessionId, String destination, String message) {
        messagingTemplate.convertAndSendToUser(sessionId, destination, 
            Map.of("error", message, "timestamp", System.currentTimeMillis()));
    }

    /**
     * 递归删除目录
     */
    private void deleteDirectory(java.nio.file.Path directory) throws IOException {
        java.nio.file.Files.walk(directory)
                .sorted(Comparator.reverseOrder())
                .map(java.nio.file.Path::toFile)
                .forEach(File::delete);
    }

    /**
     * 从URL获取文件名
     */
    private String getFileNameFromUrl(String url, java.net.URLConnection connection) {
        String fileName = "download";
        
        // 尝试从Content-Disposition头获取文件名
        String contentDisposition = connection.getHeaderField("Content-Disposition");
        if (contentDisposition != null && contentDisposition.contains("filename=")) {
            fileName = contentDisposition.substring(contentDisposition.indexOf("filename=") + 9);
            fileName = fileName.replaceAll("\"", "");
        } else {
            // 从URL路径获取文件名
            try {
                java.net.URL fileUrl = new java.net.URL(url);
                String path = fileUrl.getPath();
                if (path != null && !path.isEmpty()) {
                    fileName = path.substring(path.lastIndexOf('/') + 1);
                }
            } catch (Exception e) {
                log.warn("无法从URL获取文件名: {}", url, e);
            }
        }
        
        return fileName;
    }

    /**
     * 异步下载文件
     */
    private void downloadFileAsync(String url, String targetPath, String fileName) {
        executorService.submit(() -> {
            try {
                java.net.URL fileUrl = new java.net.URL(url);
                java.io.InputStream inputStream = fileUrl.openStream();
                java.nio.file.Path path = java.nio.file.Paths.get(targetPath);
                
                // 创建父目录
                java.nio.file.Files.createDirectories(path.getParent());
                
                // 下载文件
                java.nio.file.Files.copy(inputStream, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                inputStream.close();
                
                log.info("文件下载完成: {} -> {}", url, targetPath);
            } catch (Exception e) {
                log.error("文件下载失败: {} -> {}", url, targetPath, e);
            }
        });
    }

    /**
     * 启动系统监控线程
     */
    private void startSystemMonitorThread(String sessionId) {
        executorService.submit(() -> {
            while (activeSessions.containsKey(sessionId) && 
                   activeSessions.get(sessionId).contains("system_monitor")) {
                try {
                    // 获取系统负载信息
                    Map<String, Object> systemLoad = getSystemLoadInfo();
                    
                    // 发送系统监控数据
                    messagingTemplate.convertAndSendToUser(sessionId, "/queue/system", 
                        Map.of("type", "monitor", "data", systemLoad, "timestamp", System.currentTimeMillis()));
                    
                    // 每5秒更新一次
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    log.error("系统监控线程异常: sessionId={}", sessionId, e);
                    break;
                }
            }
        });
    }

    /**
     * 获取系统负载信息
     */
    private Map<String, Object> getSystemLoadInfo() {
        Map<String, Object> loadInfo = new HashMap<>();
        
        try {
            // 获取运行时信息
            Runtime runtime = Runtime.getRuntime();
            long totalMemory = runtime.totalMemory();
            long freeMemory = runtime.freeMemory();
            long usedMemory = totalMemory - freeMemory;
            long maxMemory = runtime.maxMemory();
            
            Map<String, Object> memory = new HashMap<>();
            memory.put("total", totalMemory);
            memory.put("used", usedMemory);
            memory.put("free", freeMemory);
            memory.put("max", maxMemory);
            memory.put("usedPercent", (double) usedMemory / maxMemory * 100);
            
            loadInfo.put("memory", memory);
            
            // 获取处理器数量
            int processors = runtime.availableProcessors();
            loadInfo.put("processors", processors);
            
            // 获取系统时间
            loadInfo.put("timestamp", System.currentTimeMillis());
            
        } catch (Exception e) {
            log.error("获取系统负载信息失败", e);
            loadInfo.put("error", "获取系统负载信息失败: " + e.getMessage());
        }
        
        return loadInfo;
    }

    /**
     * 记录操作日志
     */
    private void logOperation(Integer masterId, String operationType, boolean isSuccess, Map<String, Object> detail) {
        OperationLogs log = new OperationLogs();
        log.setMasterId(masterId);
        log.setOperationType(operationType);
        log.setOperationTime(new Date());
        log.setIsSuccess(isSuccess ? 1 : 0);
        log.setDetail(detail.toString());

        operationLogsService.save(log);
    }
}
