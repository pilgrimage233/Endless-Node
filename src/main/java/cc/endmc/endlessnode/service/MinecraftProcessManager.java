package cc.endmc.endlessnode.service;

import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.util.CommandLineParser;
import cc.endmc.endlessnode.util.CommandRestrictions;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minecraft 服务器进程管理：启停、控制台线程、资源监控、JVM 参数解析。
 * 从 ServerController 中提取，职责单一。
 */
@Slf4j
@Service
public class MinecraftProcessManager {

    private static final long RESTART_WAIT_TIME_MS = 5000;
    private static final long FORCE_KILL_TIMEOUT_SECONDS = 10;
    private static final long PROCESS_INFO_CACHE_TTL_MS = 5000L;
    private static final int DEFAULT_MEMORY_MB = 1024;
    private static final String DEFAULT_JVM_ARGS = "-XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200";

    private final Map<Integer, Object> serverLocks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, CachedProcessInfo> processInfoCache = new ConcurrentHashMap<>();
    private final ConsoleLogService consoleLogService;
    private final WebhookService webhookService;

    public MinecraftProcessManager(ConsoleLogService consoleLogService, WebhookService webhookService) {
        this.consoleLogService = consoleLogService;
        this.webhookService = webhookService;
    }

    @PreDestroy
    public void shutdown() {
        // 由 ServerController.cleanup() 处理进程关闭，此处仅清理缓存
        processInfoCache.clear();
    }

    // ==================== 服务器锁 ====================

    public Object getServerLock(Integer serverId) {
        return serverLocks.computeIfAbsent(serverId, k -> new Object());
    }

    public void removeServerLock(Integer serverId) {
        serverLocks.remove(serverId);
    }

    // ==================== 进程启停 ====================

    /**
     * 使用默认方式启动 Minecraft 服务器
     */
    public Process startServer(cc.endmc.endlessnode.domain.ServerInstances server) throws IOException {
        if (server == null) throw new IllegalArgumentException("Server instance cannot be null");
        if (server.getFilePath() == null || server.getFilePath().trim().isEmpty())
            throw new IllegalArgumentException("Server file path cannot be empty");

        List<String> command = new ArrayList<>();
        command.add("java");

        if (server.getJvmArgs() != null && !server.getJvmArgs().trim().isEmpty()) {
            command.addAll(Arrays.asList(server.getJvmArgs().trim().split("\\s+")));
        } else {
            Integer memory = server.getMemoryMb();
            if (memory == null || memory <= 0) memory = DEFAULT_MEMORY_MB;
            command.add("-Xmx" + memory + "M");
            command.add("-Xms" + (memory / 2) + "M");
        }

        String jarPath = server.getFilePath() + File.separator + getJarFileName(server);
        command.add("-jar");
        command.add(jarPath);
        command.add("nogui");

        File workingDir = prepareWorkingDir(server.getFilePath());
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(workingDir);
        pb.redirectErrorStream(true);
        setAnsiEnv(pb.environment());

        log.info("正在启动服务器 {} ，使用命令: {}", server.getId(), String.join(" ", command));
        return pb.start();
    }

    /**
     * 使用自定义脚本启动 Minecraft 服务器
     */
    public Process startServerWithScript(cc.endmc.endlessnode.domain.ServerInstances server, String script) throws IOException {
        if (server == null) throw new IllegalArgumentException("Server instance cannot be null");
        if (script == null || script.trim().isEmpty()) throw new IllegalArgumentException("Start script cannot be empty");
        if (server.getFilePath() == null || server.getFilePath().trim().isEmpty())
            throw new IllegalArgumentException("Server file path cannot be empty");

        File workingDir = prepareWorkingDir(server.getFilePath());
        String trimmedScript = script.trim();
        String osName = System.getProperty("os.name", "unknown");

        ProcessBuilder pb;
        if (osName.toLowerCase().contains("windows")) {
            CommandRestrictions.validateWindowsCmdScript(trimmedScript);
            pb = new ProcessBuilder("cmd", "/c", trimmedScript);
        } else {
            List<String> unixCmd = CommandLineParser.parse(trimmedScript);
            pb = new ProcessBuilder(unixCmd);
        }

        pb.directory(workingDir);
        pb.redirectErrorStream(true);
        setAnsiEnv(pb.environment());

        log.debug("正在使用自定义脚本启动服务器 {} (工作目录: {}): {}", server.getId(), workingDir.getAbsolutePath(), trimmedScript);
        return pb.start();
    }

    /**
     * 执行停止脚本（向进程 stdin 写入命令）
     */
    public void executeStopScript(cc.endmc.endlessnode.domain.ServerInstances server, String script) throws IOException {
        if (server == null) throw new IllegalArgumentException("Server instance cannot be null");
        if (script == null || script.trim().isEmpty()) throw new IllegalArgumentException("Stop script cannot be empty");

        Integer serverId = server.getId();
        Process process = Node.getRunningServers().get(serverId);
        if (process == null) throw new IOException("服务器未在运行");
        if (!process.isAlive()) throw new IOException("服务器进程已终止");

        OutputStreamWriter writer = getOrCreateWriter(serverId, process);
        writer.write(script.trim() + "\n");
        writer.flush();
        log.info("已为服务器 {} 执行停止脚本: {}", serverId, script.trim());
    }

    /**
     * 向运行中的服务器发送控制台命令
     */
    public void sendCommand(Integer serverId, Process process, String command) throws IOException {
        OutputStreamWriter writer = getOrCreateWriter(serverId, process);
        writer.write(command + "\n");
        writer.flush();
    }

    // ==================== 控制台线程管理 ====================

    /**
     * 启动控制台输出线程，读取进程 stdout 并推送到日志缓存和 WebSocket
     */
    public void startConsoleThread(Integer serverId, Process process) {
        if (serverId == null || process == null) return;
        stopConsoleThread(serverId);

        Thread consoleThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while (!Thread.currentThread().isInterrupted() && (line = reader.readLine()) != null) {
                    consoleLogService.addLog(serverId, line);
                    consoleLogService.dispatchToWebSocket(serverId, Map.of("line", line));
                }
            } catch (IOException e) {
                if (!process.isAlive()) {
                    log.debug("服务器控制台输出线程正常终止: {}", serverId);
                    return;
                }
                log.error("读取服务器控制台输出时发生错误: {}", serverId, e);
                consoleLogService.addLog(serverId, "[ERROR] 读取控制台失败: " + e.getMessage());
                consoleLogService.dispatchToWebSocket(serverId, Map.of("error", "读取控制台失败: " + e.getMessage()));
            }
            try {
                int exitCode = process.waitFor();
                if (exitCode != 0) {
                    log.warn("服务器进程异常退出: serverId={}, exitCode={}", serverId, exitCode);
                    webhookService.fireEvent("server.crashed",
                            "{\"serverId\":" + serverId + ",\"exitCode\":" + exitCode + "}");
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }, "ConsoleThread-" + serverId);
        consoleThread.setDaemon(true);
        consoleThread.start();
        Node.getConsoleThreads().put(serverId, consoleThread);
    }

    /**
     * 停止控制台输出线程
     */
    public void stopConsoleThread(Integer serverId) {
        if (serverId == null) return;
        Thread t = Node.getConsoleThreads().remove(serverId);
        if (t != null && t.isAlive()) {
            t.interrupt();
            try {
                t.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // ==================== 清理 ====================

    public boolean stopServerGracefully(Integer serverId, int timeoutSeconds) throws IOException, InterruptedException {
        stopConsoleThread(serverId);
        Process process = Node.getRunningServers().get(serverId);
        if (process == null || !process.isAlive()) return true;
        OutputStreamWriter writer = getOrCreateWriter(serverId, process);
        writer.write("stop\n");
        writer.flush();
        boolean exited = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly();
            process.waitFor(5, TimeUnit.SECONDS);
        }
        cleanupServer(serverId);
        return exited;
    }

    /**
     * 清理指定服务器的全部运行时资源
     */
    public void cleanupServer(Integer serverId) {
        stopConsoleThread(serverId);
        consoleLogService.unregisterServer(serverId);
        Node.getRunningServers().remove(serverId);
        Node.getServerStartTimes().remove(serverId);
        closeWriter(Node.getServerWriters().remove(serverId));
    }

    /**
     * 清理全部服务器运行时资源
     */
    public void cleanupAll() {
        for (Integer serverId : new HashSet<>(Node.getRunningServers().keySet())) {
            Process process = Node.getRunningServers().get(serverId);
            if (process != null && process.isAlive()) {
                try {
                    OutputStreamWriter w = Node.getServerWriters().get(serverId);
                    if (w != null) {
                        w.write("stop\n");
                        w.flush();
                    }
                } catch (Exception e) {
                    log.warn("向服务器 {} 发送stop命令失败: {}", serverId, e.getMessage());
                }
                try {
                    if (!process.waitFor(10, TimeUnit.SECONDS)) {
                        process.destroyForcibly();
                        process.waitFor(5, TimeUnit.SECONDS);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    process.destroyForcibly();
                }
            }
            cleanupServer(serverId);
        }
        for (Integer serverId : new HashSet<>(Node.getConsoleThreads().keySet())) {
            stopConsoleThread(serverId);
        }
        processInfoCache.clear();
    }

    // ==================== 进程信息与资源监控 ====================

    /**
     * 获取进程详细信息（PID、命令、CPU/内存使用等）
     */
    public Map<String, Object> getProcessInfo(Process process) {
        Map<String, Object> info = new HashMap<>();
        try {
            info.put("alive", process.isAlive());
            try {
                long pid = process.pid();
                info.put("pid", pid);
                try {
                    process.pid(); // 触发 ProcessHandle
                    ProcessHandle.of(pid).ifPresent(ph -> {
                        ProcessHandle.Info hi = ph.info();
                        hi.command().ifPresent(cmd -> info.put("command", cmd));
                        hi.arguments().ifPresent(args -> info.put("arguments", Arrays.asList(args)));
                        hi.startInstant().ifPresent(s -> info.put("startInstant", s.toString()));
                        hi.totalCpuDuration().ifPresent(cpu -> {
                            info.put("totalCpuDurationSeconds", cpu.getSeconds());
                            info.put("totalCpuDurationNanos", cpu.getNano());
                        });
                        hi.user().ifPresent(u -> info.put("user", u));
                    });
                } catch (Exception e) {
                    log.debug("无法获取 ProcessHandle 信息: {}", e.getMessage());
                }
                Map<String, Object> usage = getCachedResourceUsage(pid);
                if (!usage.isEmpty()) info.put("resourceUsage", usage);
            } catch (UnsupportedOperationException e) {
                info.put("pid", null);
            }
        } catch (Exception e) {
            log.error("获取进程信息时发生错误", e);
            info.put("error", e.getMessage());
        }
        return info;
    }

    /**
     * 从启动脚本中提取 JVM 参数并更新服务器配置
     */
    public void updateJvmArgsFromScript(cc.endmc.endlessnode.domain.ServerInstances server, String script,
                                         cc.endmc.endlessnode.service.ServerInstancesService serverInstancesService) {
        if (server == null || script == null || script.trim().isEmpty()) return;
        try {
            boolean needsUpdate = false;

            Pattern xmxPattern = Pattern.compile("-Xmx(\\d+)([MmGgKk]?)");
            Matcher xmxMatcher = xmxPattern.matcher(script);
            if (xmxMatcher.find()) {
                int memoryMb = Integer.parseInt(xmxMatcher.group(1));
                String unit = xmxMatcher.group(2).toUpperCase();
                if ("G".equals(unit)) memoryMb *= 1024;
                else if ("K".equals(unit)) memoryMb /= 1024;
                if (server.getMemoryMb() == null || !server.getMemoryMb().equals(memoryMb)) {
                    server.setMemoryMb(memoryMb);
                    needsUpdate = true;
                }
            }

            StringBuilder jvmArgs = new StringBuilder();
            for (String part : script.trim().split("\\s+")) {
                if ("java".equalsIgnoreCase(part)) continue;
                if ("-jar".equalsIgnoreCase(part)) break;
                if (part.startsWith("-Xms") || part.startsWith("-Xmx")) continue;
                if (part.startsWith("-")) {
                    if (jvmArgs.length() > 0) jvmArgs.append(" ");
                    jvmArgs.append(part);
                }
            }
            String extracted = jvmArgs.toString().trim();
            if (!extracted.isEmpty() && (server.getJvmArgs() == null || !server.getJvmArgs().equals(extracted))) {
                server.setJvmArgs(extracted);
                needsUpdate = true;
            }

            if (needsUpdate) {
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);
            }
        } catch (Exception e) {
            log.warn("从启动脚本提取JVM参数时发生错误: {}", e.getMessage());
        }
    }

    // ==================== 内部方法 ====================

    private Map<String, Object> getCachedResourceUsage(long pid) {
        if (pid <= 0) return Collections.emptyMap();
        long now = System.currentTimeMillis();
        CachedProcessInfo cached = processInfoCache.get(pid);
        if (cached != null && now - cached.timestamp < PROCESS_INFO_CACHE_TTL_MS) {
            return new HashMap<>(cached.data);
        }
        Map<String, Object> usage = getResourceUsage(pid);
        if (!usage.isEmpty()) {
            processInfoCache.put(pid, new CachedProcessInfo(new HashMap<>(usage), now));
        } else {
            processInfoCache.remove(pid);
        }
        return usage;
    }

    private Map<String, Object> getResourceUsage(long pid) {
        Map<String, Object> usage = new HashMap<>();
        String os = System.getProperty("os.name", "").toLowerCase();
        try {
            if (os.contains("win")) getWindowsResourceUsage(pid, usage);
            else if (os.contains("linux") || os.contains("unix") || os.contains("mac")) getUnixResourceUsage(pid, usage);
        } catch (Exception e) {
            log.debug("获取进程资源使用情况失败: {}", e.getMessage());
        }
        return usage;
    }

    private void getWindowsResourceUsage(long pid, Map<String, Object> usage) {
        try {
            ProcessBuilder pb = new ProcessBuilder("wmic", "process", "where", "ProcessId=" + pid,
                    "get", "WorkingSetSize,PageFileUsage", "/format:csv");
            Process proc = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean first = true;
                while ((line = reader.readLine()) != null) {
                    if (first || line.trim().isEmpty()) { first = false; continue; }
                    String[] parts = line.split(",");
                    if (parts.length >= 3) {
                        try {
                            String memStr = parts[parts.length - 2].trim();
                            if (!memStr.isEmpty() && !memStr.equals("WorkingSetSize")) {
                                long bytes = Long.parseLong(memStr);
                                usage.put("memoryBytes", bytes);
                                usage.put("memoryMB", bytes / (1024.0 * 1024.0));
                            }
                            String pfStr = parts[parts.length - 1].trim();
                            if (!pfStr.isEmpty() && !pfStr.equals("PageFileUsage")) {
                                long bytes = Long.parseLong(pfStr);
                                usage.put("virtualMemoryBytes", bytes);
                                usage.put("virtualMemoryMB", bytes / (1024.0 * 1024.0));
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            proc.waitFor(1, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.debug("Windows 进程信息获取失败: {}", e.getMessage());
        }
    }

    private void getUnixResourceUsage(long pid, Map<String, Object> usage) {
        try {
            ProcessBuilder pb = new ProcessBuilder("ps", "-p", String.valueOf(pid), "-o", "rss=,vsz=,%cpu=,etime=");
            Process proc = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean first = true;
                while ((line = reader.readLine()) != null) {
                    if (first) { first = false; continue; }
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 3) {
                        try {
                            long rss = Long.parseLong(parts[0]);
                            usage.put("memoryKB", rss);
                            usage.put("memoryMB", rss / 1024.0);
                            usage.put("memoryBytes", rss * 1024L);
                            long vsz = Long.parseLong(parts[1]);
                            usage.put("virtualMemoryKB", vsz);
                            usage.put("virtualMemoryMB", vsz / 1024.0);
                            usage.put("virtualMemoryBytes", vsz * 1024L);
                            usage.put("cpuPercent", Double.parseDouble(parts[2]));
                            if (parts.length >= 4) usage.put("elapsedTime", parts[3]);
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            proc.waitFor(1, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.debug("Unix 进程信息获取失败: {}", e.getMessage());
        }
    }

    private File prepareWorkingDir(String filePath) throws IOException {
        File dir = new File(filePath);
        if (!dir.exists()) {
            if (!dir.mkdirs()) throw new IOException("Failed to create working directory: " + dir.getAbsolutePath());
        }
        if (!dir.isDirectory()) throw new IOException("Path is not a directory: " + dir.getAbsolutePath());
        return dir;
    }

    private void setAnsiEnv(Map<String, String> env) {
        env.put("TERM", "xterm-256color");
        env.put("COLORTERM", "truecolor");
        env.put("FORCE_COLOR", "true");
    }

    String getJarFileName(cc.endmc.endlessnode.domain.ServerInstances server) {
        if (server == null) return "server.jar";
        String coreType = server.getCoreType();
        String version = server.getVersion();
        if (coreType == null || coreType.trim().isEmpty()) return "server.jar";
        return switch (coreType.trim().toUpperCase()) {
            case "VANILLA" -> version != null && !version.trim().isEmpty() ? "minecraft_server." + version.trim() + ".jar" : "minecraft_server.jar";
            case "PAPER" -> version != null && !version.trim().isEmpty() ? "paper-" + version.trim() + ".jar" : "paper.jar";
            case "SPIGOT" -> version != null && !version.trim().isEmpty() ? "spigot-" + version.trim() + ".jar" : "spigot.jar";
            case "FORGE" -> version != null && !version.trim().isEmpty() ? "forge-" + version.trim() + ".jar" : "forge.jar";
            case "FABRIC" -> version != null && !version.trim().isEmpty() ? "fabric-server-" + version.trim() + ".jar" : "fabric-server.jar";
            default -> "server.jar";
        };
    }

    OutputStreamWriter getOrCreateWriter(Integer serverId, Process process) throws IOException {
        OutputStreamWriter writer = Node.getServerWriters().get(serverId);
        if (writer != null) return writer;
        OutputStream os = process.getOutputStream();
        if (os == null) throw new IOException("无法获取进程输出流");
        writer = new OutputStreamWriter(os, StandardCharsets.UTF_8);
        Node.getServerWriters().put(serverId, writer);
        return writer;
    }

    private void closeWriter(Writer writer) {
        if (writer != null) {
            try { writer.close(); } catch (IOException e) { log.error("关闭Writer时发生错误", e); }
        }
    }

    /**
     * 检测指定端口是否可用（未被占用）
     */
    public boolean isPortAvailable(int port) {
        try (ServerSocket ss = new ServerSocket(port)) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 等待 Minecraft 服务器就绪（端口可连接）。
     * 在后台线程中轮询游戏端口，成功后更新状态为 RUNNING，超时则标记为 STOPPED。
     *
     * @param server          服务器实例
     * @param serverInstancesService 用于更新状态
     * @param timeoutSeconds  最大等待秒数
     * @param pollIntervalMs  轮询间隔毫秒
     */
    public void waitForServerReady(cc.endmc.endlessnode.domain.ServerInstances server,
                                    ServerInstancesService serverInstancesService,
                                    int timeoutSeconds, long pollIntervalMs) {
        if (server == null || server.getId() == null) return;
        int gamePort = server.getPort() != null ? server.getPort() : 25565;

        Thread healthCheckThread = new Thread(() -> {
            long deadline = System.currentTimeMillis() + timeoutSeconds * 1000L;
            log.info("开始健康检查：服务器 {} 端口 {}，超时 {} 秒", server.getId(), gamePort, timeoutSeconds);

            while (System.currentTimeMillis() < deadline) {
                // 如果进程已不在运行，直接退出
                Process process = Node.getRunningServers().get(server.getId());
                if (process == null || !process.isAlive()) {
                    log.warn("健康检查中止：服务器 {} 进程已终止", server.getId());
                    return;
                }

                // 尝试 TCP 连接游戏端口
                try (java.net.Socket socket = new java.net.Socket()) {
                    socket.connect(new java.net.InetSocketAddress("127.0.0.1", gamePort), 2000);
                    // 端口可连接，服务器就绪
                    log.info("健康检查通过：服务器 {} 端口 {} 已就绪", server.getId(), gamePort);
                    try {
                        server.setStatus("RUNNING");
                        server.setUpdatedAt(new Date());
                        serverInstancesService.updateById(server);
                    } catch (Exception e) {
                        log.error("更新服务器 {} 状态为 RUNNING 失败", server.getId(), e);
                    }
                    return;
                } catch (Exception e) {
                    // 端口还未就绪，等待后重试
                }

                try {
                    Thread.sleep(pollIntervalMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }

            // 超时
            log.warn("健康检查超时：服务器 {} 在 {} 秒内未就绪", server.getId(), timeoutSeconds);
            try {
                server.setStatus("STOPPED");
                server.setUpdatedAt(new Date());
                serverInstancesService.updateById(server);
            } catch (Exception e) {
                log.error("更新服务器 {} 状态失败", server.getId(), e);
            }
        }, "HealthCheck-" + server.getId());
        healthCheckThread.setDaemon(true);
        healthCheckThread.start();
    }

    private record CachedProcessInfo(Map<String, Object> data, long timestamp) {}
}
