package cc.endmc.endlessnode.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.util.Date;

@TableName("server_metrics")
@Data
public class ServerMetrics {
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;
    @TableField("server_id")
    private Integer serverId;
    @TableField("recorded_at")
    private Date recordedAt;
    @TableField("cpu_percent")
    private Double cpuPercent;
    @TableField("memory_mb")
    private Double memoryMb;
    @TableField("player_count")
    private Integer playerCount;
    @TableField("max_players")
    private Integer maxPlayers;
    @TableField("tps")
    private Double tps;
}
