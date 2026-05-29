package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.domain.ScheduledTasks;
import cc.endmc.endlessnode.domain.ServerMetrics;
import cc.endmc.endlessnode.domain.Webhooks;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 管理端点：模板部署、定时任务、Webhook、资源指标、日志查询。
 */
@RestController
@RequestMapping("/api/manage")
@RequiredArgsConstructor
public class ManagementController {

    private final TemplateService templateService;
    private final ScheduledTasksService tasksService;
    private final ScheduledTaskRunner taskRunner;
    private final WebhooksService webhooksService;
    private final WebhookService webhookService;
    private final MetricsCollector metricsCollector;
    private final ConsoleLogService consoleLogService;
    private final AccessTokensService accessTokensService;

    // ==================== 模板 ====================

    @GetMapping("/templates")
    public ResponseEntity<Map<String, Object>> listTemplates() {
        Map<String, Object> templates = new LinkedHashMap<>();
        for (var entry : Map.of(
                "paper-1.20.4", "Paper 1.20.4",
                "paper-1.21.4", "Paper 1.21.4",
                "spigot-1.20.4", "Spigot 1.20.4",
                "vanilla-1.20.4", "Vanilla 1.20.4"
        ).entrySet()) {
            var tpl = templateService.getTemplate(entry.getKey());
            if (tpl != null) {
                templates.put(entry.getKey(), Map.of(
                        "name", tpl.name(), "version", tpl.version(), "coreType", tpl.coreType()));
            }
        }
        return ResponseEntity.ok(Map.of("success", true, "templates", templates));
    }

    @PostMapping("/templates/deploy")
    public ResponseEntity<Map<String, Object>> deployTemplate(@RequestBody Map<String, Object> request,
                                                               @RequestHeader("X-Endless-Token") String token) {
        String template = (String) request.get("template");
        String instanceName = (String) request.get("instanceName");
        Number memoryMb = (Number) request.getOrDefault("memoryMb", 2048);
        Number port = (Number) request.getOrDefault("port", 25565);

        if (template == null || instanceName == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "template 和 instanceName 不能为空"));
        }

        // 获取当前用户 UUID
        var at = accessTokensService.lambdaQuery().eq(cc.endmc.endlessnode.domain.AccessTokens::getToken, token).one();
        if (at == null) return ResponseEntity.status(401).body(Map.of("error", "无效token"));

        TemplateService.DeployResult result = templateService.deploy(
                template, instanceName, memoryMb.intValue(), port.intValue(), at.getMasterUuid());

        if (result.success()) {
            return ResponseEntity.ok(Map.of("success", true, "message", result.message(), "serverId", result.serverId()));
        }
        return ResponseEntity.status(500).body(Map.of("error", result.message()));
    }

    // ==================== 定时任务 ====================

    @GetMapping("/tasks")
    public ResponseEntity<Map<String, Object>> listTasks(@RequestParam(required = false) Integer serverId) {
        var query = tasksService.lambdaQuery();
        if (serverId != null) query.eq(ScheduledTasks::getServerId, serverId);
        List<ScheduledTasks> tasks = query.list();
        return ResponseEntity.ok(Map.of("success", true, "tasks", tasks));
    }

    @PostMapping("/tasks")
    public ResponseEntity<Map<String, Object>> createTask(@RequestBody ScheduledTasks task) {
        if (task.getServerId() == null || task.getTaskType() == null || task.getCronExpression() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "serverId、taskType、cronExpression 不能为空"));
        }
        task.setCreatedAt(new Date());
        task.setEnabled(1);
        tasksService.save(task);
        taskRunner.scheduleTask(task);
        return ResponseEntity.ok(Map.of("success", true, "taskId", task.getId()));
    }

    @PutMapping("/tasks/{taskId}")
    public ResponseEntity<Map<String, Object>> updateTask(@PathVariable Integer taskId,
                                                           @RequestBody ScheduledTasks updates) {
        ScheduledTasks existing = tasksService.getById(taskId);
        if (existing == null) return ResponseEntity.notFound().build();

        if (updates.getCronExpression() != null) existing.setCronExpression(updates.getCronExpression());
        if (updates.getPayload() != null) existing.setPayload(updates.getPayload());
        if (updates.getEnabled() != null) existing.setEnabled(updates.getEnabled());
        existing.setUpdatedAt(new Date());
        tasksService.updateById(existing);
        taskRunner.scheduleTask(existing);
        return ResponseEntity.ok(Map.of("success", true));
    }

    @DeleteMapping("/tasks/{taskId}")
    public ResponseEntity<Map<String, Object>> deleteTask(@PathVariable Integer taskId) {
        taskRunner.cancelTask(taskId);
        tasksService.removeById(taskId);
        return ResponseEntity.ok(Map.of("success", true));
    }

    // ==================== Webhook ====================

    @GetMapping("/webhooks")
    public ResponseEntity<Map<String, Object>> listWebhooks() {
        return ResponseEntity.ok(Map.of("success", true, "webhooks", webhooksService.list()));
    }

    @PostMapping("/webhooks")
    public ResponseEntity<Map<String, Object>> createWebhook(@RequestBody Webhooks webhook) {
        if (webhook.getUrl() == null || webhook.getEvents() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "url 和 events 不能为空"));
        }
        webhook.setCreatedAt(new Date());
        webhook.setEnabled(1);
        webhooksService.save(webhook);
        return ResponseEntity.ok(Map.of("success", true, "webhookId", webhook.getId()));
    }

    @DeleteMapping("/webhooks/{webhookId}")
    public ResponseEntity<Map<String, Object>> deleteWebhook(@PathVariable Integer webhookId) {
        webhooksService.removeById(webhookId);
        return ResponseEntity.ok(Map.of("success", true));
    }

    // ==================== 资源指标 ====================

    @GetMapping("/servers/{serverId}/metrics")
    public ResponseEntity<Map<String, Object>> getMetrics(
            @PathVariable Integer serverId,
            @RequestParam(defaultValue = "1") int hours) {
        List<ServerMetrics> metrics = metricsCollector.queryMetrics(serverId, hours);
        return ResponseEntity.ok(Map.of("success", true, "serverId", serverId, "hours", hours, "metrics", metrics));
    }

    // ==================== 日志查询 ====================

    @GetMapping("/servers/{serverId}/logs")
    public ResponseEntity<Map<String, Object>> listLogDates(@PathVariable Integer serverId) {
        List<String> dates = consoleLogService.listLogDates(serverId);
        return ResponseEntity.ok(Map.of("success", true, "serverId", serverId, "dates", dates));
    }

    @GetMapping("/servers/{serverId}/logs/{date}")
    public ResponseEntity<Map<String, Object>> getLogByDate(
            @PathVariable Integer serverId, @PathVariable String date) {
        List<String> lines = consoleLogService.readLogFile(serverId, date);
        return ResponseEntity.ok(Map.of("success", true, "serverId", serverId, "date", date,
                "lines", lines, "count", lines.size()));
    }
}
