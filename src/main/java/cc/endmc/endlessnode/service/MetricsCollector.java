package cc.endmc.endlessnode.service;

import cc.endmc.endlessnode.domain.ServerMetrics;
import cc.endmc.endlessnode.manage.Node;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ScheduledFuture;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * 服务器资源指标采集器：定时采集 CPU/内存/在线人数并写入 SQLite。
 */
@Slf4j
@Service
public class MetricsCollector {

    private final ServerInstancesService instancesService;
    private final ServerMetricsService metricsService;
    private final MinecraftProcessManager processManager;
    private final QueryConnectionManager queryManager;
    private final ConsoleLogService consoleLogService;
    private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final ThreadPoolTaskScheduler scheduler;
    private ScheduledFuture<?> collectorFuture;

    public MetricsCollector(ServerInstancesService instancesService, ServerMetricsService metricsService,
                            MinecraftProcessManager processManager, QueryConnectionManager queryManager,
                            ConsoleLogService consoleLogService) {
        this.instancesService = instancesService;
        this.metricsService = metricsService;
        this.processManager = processManager;
        this.queryManager = queryManager;
        this.consoleLogService = consoleLogService;
        this.scheduler = new ThreadPoolTaskScheduler();
        this.scheduler.setPoolSize(1);
        this.scheduler.setThreadNamePrefix("MetricsCollector-");
    }

    @PostConstruct
    public void init() {
        scheduler.initialize();
        // 每 60 秒采集一次
        collectorFuture = scheduler.scheduleWithFixedDelay(this::collect, 30_000);
    }

    @PreDestroy
    public void shutdown() {
        if (collectorFuture != null) collectorFuture.cancel(false);
        scheduler.shutdown();
    }

    private void collect() {
        List<cc.endmc.endlessnode.domain.ServerInstances> instances = instancesService.list();
        for (var server : instances) {
            if (server.getId() == null) continue;
            Process process = Node.getRunningServers().get(server.getId());
            if (process == null || !process.isAlive()) continue;

            try {
                ServerMetrics metric = new ServerMetrics();
                metric.setServerId(server.getId());
                metric.setRecordedAt(new Date());

                // 进程资源
                Map<String, Object> info = processManager.getProcessInfo(process);
                if (info.containsKey("resourceUsage")) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> usage = (Map<String, Object>) info.get("resourceUsage");
                    if (usage.containsKey("cpuPercent")) metric.setCpuPercent(((Number) usage.get("cpuPercent")).doubleValue());
                    if (usage.containsKey("memoryMB")) metric.setMemoryMb(((Number) usage.get("memoryMB")).doubleValue());
                }

                // 在线人数
                try {
                    var qr = queryManager.queryPlayers(server.getId(), server);
                    if (qr != null && qr.success()) {
                        metric.setPlayerCount(qr.status().getOnlinePlayers());
                        metric.setMaxPlayers(qr.status().getMaxPlayers());
                    }
                } catch (Exception ignored) {}

                // TPS 采集：通过进程 stdin 发送 tps 命令并解析日志输出
                try {
                    Double tps = collectTps(server.getId(), process);
                    if (tps != null) metric.setTps(tps);
                } catch (Exception ignored) {}

                metricsService.save(metric);
            } catch (Exception e) {
                log.debug("采集指标失败: server={}", server.getId(), e);
            }
        }

        // 清理 7 天前的旧数据
        try {
            long cutoff = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000;
            metricsService.lambdaUpdate().lt(ServerMetrics::getRecordedAt, new Date(cutoff)).remove();
        } catch (Exception e) {
            log.debug("清理旧指标失败: {}", e.getMessage());
        }
    }

    /**
     * 采集 TPS：发送 tps 命令并从控制台日志缓存中解析返回值
     */
    private Double collectTps(Integer serverId, Process process) {
        return collectTpsWithMode(serverId, process, "AUTO", null);
    }

    public Double collectTpsWithMode(Integer serverId, Process process, String tpsMode, Integer sparkPort) {
        if (tpsMode == null) tpsMode = "AUTO";
        switch (tpsMode) {
            case "DISABLED" -> { return null; }
            case "TPS_COMMAND" -> { return collectTpsViaCommand(serverId, process); }
            case "SPARK_API" -> { return collectTpsViaSpark(sparkPort); }
            case "AUTO" -> {
                Double tps = collectTpsViaCommand(serverId, process);
                if (tps != null) return tps;
                return collectTpsViaSpark(sparkPort);
            }
            default -> { return null; }
        }
    }

    private Double collectTpsViaCommand(Integer serverId, Process process) {
        if (process == null || !process.isAlive()) return null;
        try {
            var writer = processManager.getOrCreateWriter(serverId, process);
            writer.write("tps\n");
            writer.flush();
            Thread.sleep(500);
            var logs = consoleLogService.getLogHistory(serverId);
            for (int i = logs.size() - 1; i >= Math.max(0, logs.size() - 20); i--) {
                String line = logs.get(i);
                if (line != null && line.contains("TPS from last")) {
                    int colonIdx = line.indexOf(':');
                    if (colonIdx > 0) {
                        String values = line.substring(colonIdx + 1).trim();
                        String first = values.split(",")[0].trim().replace("*", "");
                        return Double.parseDouble(first);
                    }
                }
            }
        } catch (Exception e) {
            log.debug("TPS 命令采集失败: server={}", serverId, e);
        }
        return null;
    }

    private Double collectTpsViaSpark(Integer sparkPort) {
        if (sparkPort == null) return null;
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("http://127.0.0.1:" + sparkPort + "/api/tps"))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                String body = resp.body().trim();
                if (body.contains("\"tps\"")) {
                    int idx = body.indexOf("\"tps\"");
                    int colonIdx = body.indexOf(':', idx);
                    int endIdx = body.indexOf(',', colonIdx);
                    if (endIdx < 0) endIdx = body.indexOf('}', colonIdx);
                    String val = body.substring(colonIdx + 1, endIdx).trim();
                    return Double.parseDouble(val);
                }
            }
        } catch (Exception e) {
            log.debug("Spark TPS 采集失败: sparkPort={}", sparkPort, e);
        }
        return null;
    }

    /**
     * 查询指定服务器的指标数据
     */
    public List<ServerMetrics> queryMetrics(Integer serverId, int hours) {
        long since = System.currentTimeMillis() - hours * 3600L * 1000;
        return metricsService.lambdaQuery()
                .eq(ServerMetrics::getServerId, serverId)
                .ge(ServerMetrics::getRecordedAt, new Date(since))
                .orderByAsc(ServerMetrics::getRecordedAt)
                .list();
    }
}
