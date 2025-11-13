package cc.endmc.endlessnode.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * 首页控制器
 */
@RestController
public class IndexController {

    @Value("${node.version:1.0}")
    private String version;

    /**
     * 获取系统信息
     */
    @GetMapping("/system/info")
    public Map<String, Object> getSystemInfo() {
        Map<String, Object> info = new HashMap<>();

        // 基础信息
        info.put("name", "Endless-Node");
        info.put("version", version);

        // 内存信息
        Runtime runtime = Runtime.getRuntime();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        long maxMemory = runtime.maxMemory();

        Map<String, Object> memory = new HashMap<>();
        memory.put("total", formatBytes(maxMemory));
        memory.put("used", formatBytes(usedMemory));
        memory.put("free", formatBytes(maxMemory - usedMemory));
        memory.put("usagePercent", (int) ((usedMemory * 100) / maxMemory));
        info.put("memory", memory);

        // 运行时间
        long uptime = ManagementFactory.getRuntimeMXBean().getUptime();
        info.put("uptime", formatUptime(uptime));

        // CPU 核心数
        info.put("cpuCores", Runtime.getRuntime().availableProcessors());

        // Java 版本
        info.put("javaVersion", System.getProperty("java.version"));

        // 操作系统信息
        info.put("osName", System.getProperty("os.name"));
        info.put("osVersion", System.getProperty("os.version"));
        info.put("osArch", System.getProperty("os.arch"));

        // 服务器时间
        info.put("serverTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));

        return info;
    }

    /**
     * 格式化字节大小
     */
    private String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.2f MB", bytes / (1024.0 * 1024));
        } else {
            return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
        }
    }

    /**
     * 格式化运行时间
     */
    private String formatUptime(long uptime) {
        long seconds = uptime / 1000;
        long days = seconds / 86400;
        long hours = (seconds % 86400) / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;

        if (days > 0) {
            return String.format("%d 天 %d 小时 %d 分钟", days, hours, minutes);
        } else if (hours > 0) {
            return String.format("%d 小时 %d 分钟", hours, minutes);
        } else if (minutes > 0) {
            return String.format("%d 分钟 %d 秒", minutes, secs);
        } else {
            return String.format("%d 秒", secs);
        }
    }
}
