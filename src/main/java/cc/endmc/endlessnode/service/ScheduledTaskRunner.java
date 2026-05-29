package cc.endmc.endlessnode.service;

import cc.endmc.endlessnode.domain.ScheduledTasks;
import cc.endmc.endlessnode.manage.Node;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;

/**
 * 定时任务运行器：加载 DB 中的定时任务，按 cron 表达式调度执行。
 */
@Slf4j
@Service
public class ScheduledTaskRunner {

    private final ScheduledTasksService tasksService;
    private final ServerInstancesService instancesService;
    private final MinecraftProcessManager processManager;
    private final BackupService backupService;
    private final WebhookService webhookService;
    private final ThreadPoolTaskScheduler scheduler;
    private final Map<Integer, ScheduledFuture<?>> runningTasks = new ConcurrentHashMap<>();

    public ScheduledTaskRunner(ScheduledTasksService tasksService, ServerInstancesService instancesService,
                               MinecraftProcessManager processManager, BackupService backupService,
                               WebhookService webhookService) {
        this.tasksService = tasksService;
        this.instancesService = instancesService;
        this.processManager = processManager;
        this.backupService = backupService;
        this.webhookService = webhookService;
        this.scheduler = new ThreadPoolTaskScheduler();
        this.scheduler.setPoolSize(4);
        this.scheduler.setThreadNamePrefix("ScheduledTask-");
        this.scheduler.setWaitForTasksToCompleteOnShutdown(true);
        this.scheduler.setAwaitTerminationSeconds(10);
    }

    @PostConstruct
    public void init() {
        scheduler.initialize();
        loadAllTasks();
    }

    @PreDestroy
    public void shutdown() {
        scheduler.shutdown();
    }

    /**
     * 加载数据库中所有启用的定时任务
     */
    public void loadAllTasks() {
        runningTasks.values().forEach(f -> f.cancel(false));
        runningTasks.clear();

        java.util.List<ScheduledTasks> tasks = tasksService.lambdaQuery().eq(ScheduledTasks::getEnabled, 1).list();
        for (ScheduledTasks task : tasks) {
            scheduleTask(task);
        }
        log.info("已加载 {} 个定时任务", tasks.size());
    }

    /**
     * 调度单个任务
     */
    public void scheduleTask(ScheduledTasks task) {
        if (task == null || task.getId() == null) return;
        // 先取消旧的
        ScheduledFuture<?> old = runningTasks.remove(task.getId());
        if (old != null) old.cancel(false);

        if (task.getEnabled() == null || task.getEnabled() == 0) return;

        try {
            CronTrigger trigger = new CronTrigger(task.getCronExpression());
            ScheduledFuture<?> future = scheduler.schedule(() -> executeTask(task), trigger);
            runningTasks.put(task.getId(), future);
            log.debug("定时任务已调度: id={}, type={}, cron={}", task.getId(), task.getTaskType(), task.getCronExpression());
        } catch (Exception e) {
            log.error("调度定时任务失败: id={}, cron={}", task.getId(), task.getCronExpression(), e);
        }
    }

    /**
     * 取消单个任务
     */
    public void cancelTask(Integer taskId) {
        ScheduledFuture<?> future = runningTasks.remove(taskId);
        if (future != null) future.cancel(false);
    }

    public void createScheduledTask(Integer serverId, String taskType, String cronExpression, String payload) {
        ScheduledTasks task = new ScheduledTasks();
        task.setServerId(serverId);
        task.setTaskType(taskType);
        task.setCronExpression(cronExpression);
        task.setPayload(payload);
        task.setEnabled(1);
        task.setCreatedAt(new Date());
        tasksService.save(task);
        scheduleTask(task);
    }

    private void executeTask(ScheduledTasks task) {
        log.info("执行定时任务: id={}, type={}, server={}", task.getId(), task.getTaskType(), task.getServerId());
        try {
            switch (task.getTaskType()) {
                case "RESTART" -> executeRestart(task);
                case "COMMAND" -> executeCommand(task);
                case "BACKUP" -> executeBackup(task);
                default -> log.warn("未知的定时任务类型: {}", task.getTaskType());
            }
        } catch (Exception e) {
            log.error("定时任务执行失败: id={}", task.getId(), e);
        }
    }

    private void executeRestart(ScheduledTasks task) {
        var server = instancesService.getById(task.getServerId());
        if (server == null) return;
        var process = Node.getRunningServers().get(task.getServerId());
        if (process != null && process.isAlive()) {
            try {
                var writer = processManager.getOrCreateWriter(task.getServerId(), process);
                writer.write("stop\n");
                writer.flush();
                process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception e) {
                log.warn("定时重启停止失败: {}", e.getMessage());
            }
        }
        processManager.cleanupServer(task.getServerId());
        try {
            Thread.sleep(5000);
            Process newProcess = processManager.startServer(server);
            Node.getRunningServers().put(task.getServerId(), newProcess);
            Node.getServerStartTimes().put(task.getServerId(), System.currentTimeMillis());
            processManager.startConsoleThread(task.getServerId(), newProcess);
            server.setStatus("STARTING");
            server.setUpdatedAt(new Date());
            instancesService.updateById(server);
            processManager.waitForServerReady(server, instancesService, 120, 3000);
            webhookService.fireEvent("server.restart", "{\"serverId\":" + task.getServerId() + "}");
        } catch (Exception e) {
            log.error("定时重启启动失败: {}", e.getMessage());
        }
    }

    private void executeCommand(ScheduledTasks task) {
        String command = task.getPayload();
        if (command == null || command.isEmpty()) return;
        var process = Node.getRunningServers().get(task.getServerId());
        if (process == null || !process.isAlive()) return;
        try {
            var writer = processManager.getOrCreateWriter(task.getServerId(), process);
            writer.write(command + "\n");
            writer.flush();
        } catch (Exception e) {
            log.error("定时命令执行失败: {}", e.getMessage());
        }
    }

    private void executeBackup(ScheduledTasks task) {
        var server = instancesService.getById(task.getServerId());
        if (server == null) return;
        // 委托给 BackupService 执行实际备份
        try {
            backupService.backupServer(server);
            webhookService.fireEvent("backup.scheduled", "{\"serverId\":" + task.getServerId() + ",\"success\":true}");
            log.info("定时备份完成: serverId={}", task.getServerId());
        } catch (Exception e) {
            log.error("定时备份失败: serverId={}", task.getServerId(), e);
            webhookService.fireEvent("backup.scheduled", "{\"serverId\":" + task.getServerId() + ",\"success\":false,\"error\":\"" + e.getMessage() + "\"}");
        }
    }
}
