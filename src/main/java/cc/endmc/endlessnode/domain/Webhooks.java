package cc.endmc.endlessnode.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.util.Date;

@TableName("webhooks")
@Data
public class Webhooks {
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;
    @TableField("url")
    private String url;
    @TableField("events")
    private String events;
    @TableField("enabled")
    private Integer enabled;
    @TableField("created_at")
    private Date createdAt;
}
