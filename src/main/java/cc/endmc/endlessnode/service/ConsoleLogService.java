package cc.endmc.endlessnode.service;

import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

/**
 * 控制台日志：内存缓存 + 磁盘持久化 + WebSocket 派发。
 */
@Slf4j
@Service
public class ConsoleLogService {

    private static final String TOPIC_CONSOLE = "/topic/console/";
    private static final int MAX_CONSOLE_LOG_LINES = 2000;
    private static final int DISPATCH_QUEUE_CAPACITY = 2048;
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    private final ConcurrentHashMap<Integer, LinkedBlockingDeque<String>> logCache = new ConcurrentHashMap<>();
    /** serverId → 日志目录 ({serverDir}/logs) */
    private final ConcurrentHashMap<Integer, Path> logDirs = new ConcurrentHashMap<>();
    private final BlockingQueue<Runnable> dispatchQueue = new LinkedBlockingQueue<>(DISPATCH_QUEUE_CAPACITY);
    private final ExecutorService dispatchExecutor;
    private final SimpMessagingTemplate messagingTemplate;

    public ConsoleLogService(SimpMessagingTemplate messagingTemplate) {
        this.messagingTemplate = messagingTemplate;
        this.dispatchExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ConsoleDispatch");
            t.setDaemon(true);
            return t;
        });
        dispatchExecutor.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    dispatchQueue.take().run();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    log.error("控制台消息派发失败", e);
                }
            }
        });
    }

    @PreDestroy
    public void shutdown() {
        dispatchExecutor.shutdownNow();
        dispatchQueue.clear();
    }

    /**
     * 注册服务器的日志目录（启动时调用）
     */
    public void registerServer(Integer serverId, String serverFilePath) {
        if (serverId == null || serverFilePath == null) return;
        Path logsDir = Paths.get(serverFilePath, "logs").toAbsolutePath().normalize();
        try {
            Files.createDirectories(logsDir);
        } catch (IOException e) {
            log.error("创建日志目录失败: {}", logsDir, e);
        }
        logDirs.put(serverId, logsDir);
    }

    /**
     * 注销服务器（停止时调用）
     */
    public void unregisterServer(Integer serverId) {
        logDirs.remove(serverId);
    }

    /**
     * 添加一行日志：内存缓存 + 磁盘写入
     */
    public void addLog(Integer serverId, String logLine) {
        if (serverId == null || logLine == null) return;

        // 内存缓存
        LinkedBlockingDeque<String> cache = logCache.computeIfAbsent(
                serverId, k -> new LinkedBlockingDeque<>(MAX_CONSOLE_LOG_LINES));
        while (!cache.offerLast(logLine)) {
            cache.pollFirst();
        }

        // 磁盘写入（异步）
        Path logDir = logDirs.get(serverId);
        if (logDir != null) {
            dispatchQueue.offer(() -> writeToDisk(logDir, logLine));
        }
    }

    public List<String> getLogHistory(Integer serverId) {
        if (serverId == null) return new ArrayList<>();
        LinkedBlockingDeque<String> cache = logCache.get(serverId);
        return cache == null ? new ArrayList<>() : new ArrayList<>(cache);
    }

    public void clearLogHistory(Integer serverId) {
        if (serverId == null) return;
        logCache.remove(serverId);
    }

    /**
     * 从磁盘读取指定日期的日志
     */
    public List<String> readLogFile(Integer serverId, String date) {
        if (serverId == null || date == null) return List.of();
        Path logDir = logDirs.get(serverId);
        if (logDir == null) return List.of();
        Path logFile = logDir.resolve("console-" + date + ".log");
        if (!Files.exists(logFile)) return List.of();
        try {
            return Files.readAllLines(logFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("读取日志文件失败: {}", logFile, e);
            return List.of();
        }
    }

    /**
     * 获取指定服务器最近 N 天的日志日期列表
     */
    public List<String> listLogDates(Integer serverId) {
        if (serverId == null) return List.of();
        Path logDir = logDirs.get(serverId);
        if (logDir == null || !Files.exists(logDir)) return List.of();
        List<String> dates = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(logDir, "console-*.log")) {
            for (Path p : stream) {
                String name = p.getFileName().toString();
                // console-2025-05-28.log → 2025-05-28
                if (name.startsWith("console-") && name.endsWith(".log")) {
                    dates.add(name.substring(8, name.length() - 4));
                }
            }
        } catch (IOException e) {
            log.error("列出日志文件失败: {}", logDir, e);
        }
        dates.sort(Collections.reverseOrder());
        return dates;
    }

    public void dispatchToWebSocket(Integer serverId, Map<String, Object> payload) {
        if (serverId == null || payload == null) return;
        Runnable task = () -> messagingTemplate.convertAndSend(TOPIC_CONSOLE + serverId, payload);
        if (!dispatchQueue.offer(task)) {
            dispatchQueue.poll();
            if (!dispatchQueue.offer(task)) {
                log.warn("控制台消息队列已满，丢弃服务器 {} 的消息", serverId);
            }
        }
    }

    private void writeToDisk(Path logDir, String line) {
        try {
            String fileName = "console-" + DATE_FMT.format(LocalDate.now()) + ".log";
            Path logFile = logDir.resolve(fileName);
            Files.write(logFile, (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.debug("写入日志文件失败: {}", e.getMessage());
        }
    }
}
