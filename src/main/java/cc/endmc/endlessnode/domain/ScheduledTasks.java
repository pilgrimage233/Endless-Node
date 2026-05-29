package cc.endmc.endlessnode.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.util.Date;

@TableName("scheduled_tasks")
@Data
public class ScheduledTasks {
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;
    @TableField("server_id")
    private Integer serverId;
    @TableField("task_type")
    private String taskType;
    @TableField("cron_expression")
    private String cronExpression;
    @TableField("payload")
    private String payload;
    @TableField("enabled")
    private Integer enabled;
    @TableField("created_at")
    private Date createdAt;
    @TableField("updated_at")
    private Date updatedAt;
}
