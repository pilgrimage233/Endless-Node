package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.OperationLogs;
import cc.endmc.endlessnode.domain.ServerInstances;
import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.service.OperationLogsService;
import cc.endmc.endlessnode.service.ServerInstancesService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 服务器实例控制器
 * 处理服务器实例的启动、停止、重启等操作
 */
@Controller
@RequestMapping("/api/servers")
@RequiredArgsConstructor
public class ServerController {

    private final AccessTokensService accessTokensService;
    private final ServerInstancesService serverInstancesService;
    private final OperationLogsService operationLogsService;
    private final SimpMessagingTemplate messagingTemplate;

    // 存储正在运行的服务器进程
    private final Map<Integer, Process> runningServers = new ConcurrentHashMap<>();

    // 存储服务器控制台输出线程
    private final Map<Integer, Thread> consoleThreads = new ConcurrentHashMap<>();

    // 线程池，用于管理控制台输出线程
    private final ExecutorService executorService = Executors.newCachedThreadPool();

    /**
     * 获取服务器实例列表
     *
     * @param token 访问令牌
     * @return 服务器实例列表
     */
    @GetMapping("/list")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> listServers(@RequestParam String token) {
        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例列表
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

        Map<String, Object> response = new HashMap<>();
        response.put("servers", instances);

        return ResponseEntity.ok(response);
    }

    /**
     * 创建服务器实例
     *
     * @param token  访问令牌
     * @param server 服务器实例信息
     * @return 创建结果
     */
    @PostMapping("/create")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> createServer(
            @RequestParam String token,
            @RequestBody ServerInstances server) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 检查实例数量限制
        long instanceCount = serverInstancesService.lambdaQuery()
                .eq(ServerInstances::getCreatedBy, accessToken.getMasterId())
                .count();

        if (instanceCount >= 20) { // 默认最大实例数
            return ResponseEntity.badRequest().body(Map.of("error", "已达到最大实例数量限制"));
        }

        // 设置默认值
        if (server.getMemoryMb() == null || server.getMemoryMb() <= 0) {
            server.setMemoryMb(1024); // 默认内存
        }

        if (server.getJvmArgs() == null || server.getJvmArgs().isEmpty()) {
            server.setJvmArgs("-XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200"); // 默认JVM参数
        }

        // 设置创建者
        server.setCreatedBy(accessToken.getMasterId());
        server.setCreatedAt(new Date());
        server.setStatus("STOPPED");

        // 保存服务器实例
        serverInstancesService.save(server);

        // 记录操作日志
        logOperation(accessToken.getMasterId(), "CREATE_SERVER", true,
                Map.of("instanceId", server.getId(), "instanceName", server.getInstanceName()));

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("serverId", server.getId());

        return ResponseEntity.ok(response);
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
    @ResponseBody
    public ResponseEntity<Map<String, Object>> startServer(
            @RequestParam String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> startScript) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否已运行
        if (runningServers.containsKey(serverId)) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器已经在运行中"));
        }

        try {
            // 启动服务器
            Process process;
            if (startScript != null && startScript.containsKey("script")) {
                // 使用主控端提供的启动脚本
                process = startMinecraftServerWithScript(server, startScript.get("script"));
            } else {
                // 使用默认启动方式
                process = startMinecraftServer(server);
            }

            runningServers.put(serverId, process);

            // 启动控制台输出线程
            startConsoleOutputThread(serverId, process);

            // 更新服务器状态
            server.setStatus("RUNNING");
            server.setUpdatedAt(new Date());
            serverInstancesService.updateById(server);

            // 记录操作日志
            logOperation(accessToken.getMasterId(), "START_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "服务器启动成功");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录操作日志
            logOperation(accessToken.getMasterId(), "START_SERVER", false,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

            return ResponseEntity.status(500).body(Map.of("error", "启动服务器失败: " + e.getMessage()));
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
    @ResponseBody
    public ResponseEntity<Map<String, Object>> stopServer(
            @RequestParam String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> stopScript) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否已停止
        Process process = runningServers.get(serverId);
        if (process == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        try {
            // 停止控制台输出线程
            stopConsoleOutputThread(serverId);

            // 停止服务器
            if (stopScript != null && stopScript.containsKey("script")) {
                // 使用主控端提供的停止脚本
                executeStopScript(server, stopScript.get("script"));
            } else {
                // 使用默认停止方式
                process.destroy();
            }

            runningServers.remove(serverId);

            // 更新服务器状态
            server.setStatus("STOPPED");
            server.setUpdatedAt(new Date());
            serverInstancesService.updateById(server);

            // 记录操作日志
            logOperation(accessToken.getMasterId(), "STOP_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "服务器停止成功");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录操作日志
            logOperation(accessToken.getMasterId(), "STOP_SERVER", false,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

            return ResponseEntity.status(500).body(Map.of("error", "停止服务器失败: " + e.getMessage()));
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
    @ResponseBody
    public ResponseEntity<Map<String, Object>> restartServer(
            @RequestParam String token,
            @PathVariable Integer serverId,
            @RequestBody(required = false) Map<String, String> scripts) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否已停止
        Process process = runningServers.get(serverId);
        if (process == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        try {
            // 停止控制台输出线程
            stopConsoleOutputThread(serverId);

            // 停止服务器
            if (scripts != null && scripts.containsKey("stopScript")) {
                // 使用主控端提供的停止脚本
                executeStopScript(server, scripts.get("stopScript"));
            } else {
                // 使用默认停止方式
                process.destroy();
            }

            runningServers.remove(serverId);

            // 等待进程完全终止
            Thread.sleep(5000);

            // 启动服务器
            Process newProcess;
            if (scripts != null && scripts.containsKey("startScript")) {
                // 使用主控端提供的启动脚本
                newProcess = startMinecraftServerWithScript(server, scripts.get("startScript"));
            } else {
                // 使用默认启动方式
                newProcess = startMinecraftServer(server);
            }

            runningServers.put(serverId, newProcess);

            // 启动控制台输出线程
            startConsoleOutputThread(serverId, newProcess);

            // 更新服务器状态
            server.setStatus("RUNNING");
            server.setUpdatedAt(new Date());
            serverInstancesService.updateById(server);

            // 记录操作日志
            logOperation(accessToken.getMasterId(), "RESTART_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "服务器重启成功");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录操作日志
            logOperation(accessToken.getMasterId(), "RESTART_SERVER", false,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

            return ResponseEntity.status(500).body(Map.of("error", "重启服务器失败: " + e.getMessage()));
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
    @ResponseBody
    public ResponseEntity<Map<String, Object>> killServer(
            @RequestParam String token,
            @PathVariable Integer serverId) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否已停止
        Process process = runningServers.get(serverId);
        if (process == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        try {
            // 停止控制台输出线程
            stopConsoleOutputThread(serverId);

            // 强制终止进程
            process.destroyForcibly();

            // 等待进程完全终止
            if (!process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                // 如果进程仍然存在，记录警告
                logOperation(accessToken.getMasterId(), "KILL_SERVER", false,
                        Map.of("instanceId", serverId, "instanceName", server.getInstanceName(),
                                "warning", "进程在10秒内未终止"));
            }

            runningServers.remove(serverId);

            // 更新服务器状态
            server.setStatus("STOPPED");
            server.setUpdatedAt(new Date());
            serverInstancesService.updateById(server);

            // 记录操作日志
            logOperation(accessToken.getMasterId(), "KILL_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "服务器强制终止成功");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录操作日志
            logOperation(accessToken.getMasterId(), "KILL_SERVER", false,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

            return ResponseEntity.status(500).body(Map.of("error", "强制终止服务器失败: " + e.getMessage()));
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
    @ResponseBody
    public ResponseEntity<Map<String, Object>> deleteServer(
            @RequestParam String token,
            @PathVariable Integer serverId) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否正在运行
        if (runningServers.containsKey(serverId)) {
            return ResponseEntity.badRequest().body(Map.of("error", "无法删除正在运行的服务器"));
        }

        try {
            // 删除服务器实例
            serverInstancesService.removeById(serverId);

            // 记录操作日志
            logOperation(accessToken.getMasterId(), "DELETE_SERVER", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName()));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "服务器删除成功");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录操作日志
            logOperation(accessToken.getMasterId(), "DELETE_SERVER", false,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "error", e.getMessage()));

            return ResponseEntity.status(500).body(Map.of("error", "删除服务器失败: " + e.getMessage()));
        }
    }

    /**
     * 获取服务器控制台输出
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     * @return 控制台输出
     */
    @GetMapping("/{serverId}/console")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getConsole(
            @RequestParam String token,
            @PathVariable Integer serverId) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            messagingTemplate.convertAndSend("/topic/console/" + serverId,
                    Map.of("error", "未找到服务器"));
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否正在运行
        Process process = runningServers.get(serverId);
        if (process == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        try {
            // 读取控制台输出
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            Map<String, Object> response = new HashMap<>();
            response.put("console", output.toString());

            return ResponseEntity.ok(response);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(Map.of("error", "读取控制台失败: " + e.getMessage()));
        }
    }

    /**
     * 向服务器发送命令
     *
     * @param token    访问令牌
     * @param serverId 服务器实例ID
     *                 // * @param command  命令
     * @return 命令执行结果
     */
    @PostMapping("/{serverId}/command")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendCommand(
            @RequestParam String token,
            @PathVariable Integer serverId,
            @RequestBody Map<String, String> request) {

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            return ResponseEntity.notFound().build();
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            return ResponseEntity.status(403).body(Map.of("error", "权限不足"));
        }

        // 检查服务器是否正在运行
        Process process = runningServers.get(serverId);
        if (process == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "服务器未在运行"));
        }

        String command = request.get("command");
        if (command == null || command.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "命令不能为空"));
        }

        try {
            // 发送命令到服务器


            // 记录操作日志
            logOperation(accessToken.getMasterId(), "SEND_COMMAND", true,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "command", command));

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "命令发送成功");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录操作日志
            logOperation(accessToken.getMasterId(), "SEND_COMMAND", false,
                    Map.of("instanceId", serverId, "instanceName", server.getInstanceName(), "command", command, "error", e.getMessage()));

            return ResponseEntity.status(500).body(Map.of("error", "发送命令失败: " + e.getMessage()));
        }
    }

    /**
     * WebSocket消息处理 - 订阅服务器控制台
     *
     * @param request 请求参数
     */
    @MessageMapping("/console/subscribe")
    public void subscribeConsole(@Payload Map<String, Object> request) {
        Integer serverId = (Integer) request.get("serverId");
        String token = (String) request.get("token");

        // 获取令牌信息
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 获取服务器实例
        ServerInstances server = serverInstancesService.getById(serverId);
        if (server == null) {
            messagingTemplate.convertAndSend("/topic/console/" + serverId,
                    Map.of("error", "未找到服务器"));
            return;
        }

        // 检查权限
        if (!server.getCreatedBy().equals(accessToken.getMasterId())) {
            messagingTemplate.convertAndSend("/topic/console/" + serverId,
                    Map.of("error", "权限不足"));
            return;
        }

        // 检查服务器是否正在运行
        Process process = runningServers.get(serverId);
        if (process == null) {
            messagingTemplate.convertAndSend("/topic/console/" + serverId,
                    Map.of("error", "服务器未在运行"));
            return;
        }

        // 发送订阅成功消息
        messagingTemplate.convertAndSend("/topic/console/" + serverId,
                Map.of("message", "已订阅控制台输出"));
    }

    /**
     * 启动控制台输出线程
     *
     * @param serverId 服务器ID
     * @param process  进程对象
     */
    private void startConsoleOutputThread(Integer serverId, Process process) {
        // 如果已经有线程在运行，先停止它
        stopConsoleOutputThread(serverId);

        // 创建新的线程来读取控制台输出
        Thread consoleThread = new Thread(() -> {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    // 发送控制台输出到WebSocket
                    final String finalLine = line;
                    messagingTemplate.convertAndSend("/topic/console/" + serverId,
                            Map.of("line", finalLine));
                }
            } catch (IOException e) {
                // 如果进程已经终止，这是正常的
                if (!process.isAlive()) {
                    return;
                }

                // 否则，记录错误
                messagingTemplate.convertAndSend("/topic/console/" + serverId,
                        Map.of("error", "读取控制台失败: " + e.getMessage()));
            }
        });

        // 设置为守护线程，这样当主线程结束时，这个线程也会结束
        consoleThread.setDaemon(true);

        // 启动线程
        consoleThread.start();

        // 保存线程引用
        consoleThreads.put(serverId, consoleThread);
    }

    /**
     * 停止控制台输出线程
     *
     * @param serverId 服务器ID
     */
    private void stopConsoleOutputThread(Integer serverId) {
        Thread consoleThread = consoleThreads.remove(serverId);
        if (consoleThread != null) {
            // 中断线程
            consoleThread.interrupt();
        }
    }

    /**
     * 启动Minecraft服务器
     *
     * @param server 服务器实例
     * @return 进程对象
     * @throws IOException IO异常
     */
    private Process startMinecraftServer(ServerInstances server) throws IOException {
        // 构建启动命令
        List<String> command = new ArrayList<>();
        command.add("java");

        // 添加JVM参数
        if (server.getJvmArgs() != null && !server.getJvmArgs().isEmpty()) {
            command.addAll(Arrays.asList(server.getJvmArgs().split("\\s+")));
        } else {
            // 默认JVM参数
            command.add("-Xmx" + server.getMemoryMb() + "M");
            command.add("-Xms" + (server.getMemoryMb() / 2) + "M");
        }

        // 添加jar文件路径
        String jarPath = server.getFilePath() + "/" + getJarFileName(server);
        command.add("-jar");
        command.add(jarPath);

        // 添加服务器参数
        command.add("nogui");

        // 创建工作目录
        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            workingDir.mkdirs();
        }

        // 启动进程
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(workingDir);
        processBuilder.redirectErrorStream(true);

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
        // 创建工作目录
        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            workingDir.mkdirs();
        }

        // 创建临时脚本文件
        File scriptFile = new File(workingDir, "start.sh");
        java.nio.file.Files.write(scriptFile.toPath(), script.getBytes());
        scriptFile.setExecutable(true);

        // 启动进程
        ProcessBuilder processBuilder = new ProcessBuilder(scriptFile.getAbsolutePath());
        processBuilder.directory(workingDir);
        processBuilder.redirectErrorStream(true);

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
        // 创建工作目录
        File workingDir = new File(server.getFilePath());
        if (!workingDir.exists()) {
            workingDir.mkdirs();
        }

        // 创建临时脚本文件
        File scriptFile = new File(workingDir, "stop.sh");
        java.nio.file.Files.write(scriptFile.toPath(), script.getBytes());
        scriptFile.setExecutable(true);

        // 执行脚本
        ProcessBuilder processBuilder = new ProcessBuilder(scriptFile.getAbsolutePath());
        processBuilder.directory(workingDir);
        processBuilder.start();

        // 等待脚本执行完成
        try {
            processBuilder.start().waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("停止脚本被中断", e);
        }
    }

    /**
     * 获取服务器jar文件名
     *
     * @param server 服务器实例
     * @return jar文件名
     */
    private String getJarFileName(ServerInstances server) {
        // 根据核心类型和版本获取jar文件名
        // 这里只是一个示例，实际实现可能需要从配置或下载获取
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
     * 记录操作日志
     *
     * @param masterId      主控端ID
     * @param operationType 操作类型
     * @param isSuccess     是否成功
     * @param detail        详细信息
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