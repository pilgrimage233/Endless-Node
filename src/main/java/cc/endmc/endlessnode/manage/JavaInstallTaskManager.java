package cc.endmc.endlessnode.manage;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Java安装任务管理器
 * 用于管理安装任务的生命周期和取消操作
 */
@Slf4j
@Service
public class JavaInstallTaskManager {

    // 存储所有活动的安装任务
    private final Map<String, InstallTask> tasks = new ConcurrentHashMap<>();

    /**
     * 创建新的安装任务
     */
    public InstallTask createTask(SseEmitter emitter) {
        String taskId = UUID.randomUUID().toString();
        InstallTask task = new InstallTask(taskId, emitter);
        tasks.put(taskId, task);
        log.info("创建安装任务: {}", taskId);
        return task;
    }

    /**
     * 获取任务
     */
    public InstallTask getTask(String taskId) {
        return tasks.get(taskId);
    }

    /**
     * 取消任务
     */
    public boolean cancelTask(String taskId) {
        InstallTask task = tasks.get(taskId);
        if (task != null) {
            task.cancel();
            log.info("任务已标记为取消: {}", taskId);
            return true;
        }
        log.warn("未找到任务: {}", taskId);
        return false;
    }

    /**
     * 完成任务
     */
    public void completeTask(String taskId, boolean success) {
        InstallTask task = tasks.get(taskId);
        if (task != null) {
            task.setStatus(success ? "completed" : "failed");
            log.info("任务完成: {}, 状态: {}", taskId, task.getStatus());
            // 延迟移除任务，给前端一些时间获取最终状态
            new Thread(() -> {
                try {
                    Thread.sleep(30000); // 30秒后清理
                    tasks.remove(taskId);
                    log.info("任务已清理: {}", taskId);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
    }

    /**
     * 移除任务
     */
    public void removeTask(String taskId) {
        tasks.remove(taskId);
        log.info("任务已移除: {}", taskId);
    }

    /**
     * 清理超时任务（超过1小时）
     */
    public void cleanupExpiredTasks() {
        long now = System.currentTimeMillis();
        long timeout = 3600000; // 1小时

        tasks.entrySet().removeIf(entry -> {
            InstallTask task = entry.getValue();
            if (now - task.getCreateTime() > timeout) {
                log.info("清理超时任务: {}", task.getTaskId());
                return true;
            }
            return false;
        });
    }

    /**
     * 获取活动任务数量
     */
    public int getActiveTaskCount() {
        return tasks.size();
    }

    /**
     * 安装任务信息
     */
    public static class InstallTask {
        private final String taskId;
        private final AtomicBoolean cancelled;
        private final SseEmitter emitter;
        private final long createTime;
        private volatile String status; // running, completed, cancelled, failed

        public InstallTask(String taskId, SseEmitter emitter) {
            this.taskId = taskId;
            this.cancelled = new AtomicBoolean(false);
            this.emitter = emitter;
            this.createTime = System.currentTimeMillis();
            this.status = "running";
        }

        public String getTaskId() {
            return taskId;
        }

        public boolean isCancelled() {
            return cancelled.get();
        }

        public void cancel() {
            cancelled.set(true);
            status = "cancelled";
        }

        public SseEmitter getEmitter() {
            return emitter;
        }

        public long getCreateTime() {
            return createTime;
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }
    }
}
