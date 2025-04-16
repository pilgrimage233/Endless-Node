package cc.endmc.endlessnode.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

/**
 * @TableName operation_logs
 */
@TableName(value = "operation_logs")
@Data
public class OperationLogs implements Serializable {
    @TableField(exist = false)
    private static final long serialVersionUID = 1L;
    /**
     *
     */
    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;
    /**
     *
     */
    @TableField(value = "master_id")
    private Integer masterId;
    /**
     *
     */
    @TableField(value = "operation_type")
    private String operationType;
    /**
     *
     */
    @TableField(value = "operation_time")
    private Date operationTime;
    /**
     *
     */
    @TableField(value = "is_success")
    private Integer isSuccess;
    /**
     *
     */
    @TableField(value = "detail")
    private String detail;
    /**
     *
     */
    @TableField(value = "target_instance_id")
    private Integer targetInstanceId;
    /**
     *
     */
    @TableField(value = "client_ip")
    private String clientIp;
    /**
     *
     */
    @TableField(value = "user_agent")
    private String userAgent;

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (that == null) {
            return false;
        }
        if (getClass() != that.getClass()) {
            return false;
        }
        OperationLogs other = (OperationLogs) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
                && (this.getMasterId() == null ? other.getMasterId() == null : this.getMasterId().equals(other.getMasterId()))
                && (this.getOperationType() == null ? other.getOperationType() == null : this.getOperationType().equals(other.getOperationType()))
                && (this.getOperationTime() == null ? other.getOperationTime() == null : this.getOperationTime().equals(other.getOperationTime()))
                && (this.getIsSuccess() == null ? other.getIsSuccess() == null : this.getIsSuccess().equals(other.getIsSuccess()))
                && (this.getDetail() == null ? other.getDetail() == null : this.getDetail().equals(other.getDetail()))
                && (this.getTargetInstanceId() == null ? other.getTargetInstanceId() == null : this.getTargetInstanceId().equals(other.getTargetInstanceId()))
                && (this.getClientIp() == null ? other.getClientIp() == null : this.getClientIp().equals(other.getClientIp()))
                && (this.getUserAgent() == null ? other.getUserAgent() == null : this.getUserAgent().equals(other.getUserAgent()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getMasterId() == null) ? 0 : getMasterId().hashCode());
        result = prime * result + ((getOperationType() == null) ? 0 : getOperationType().hashCode());
        result = prime * result + ((getOperationTime() == null) ? 0 : getOperationTime().hashCode());
        result = prime * result + ((getIsSuccess() == null) ? 0 : getIsSuccess().hashCode());
        result = prime * result + ((getDetail() == null) ? 0 : getDetail().hashCode());
        result = prime * result + ((getTargetInstanceId() == null) ? 0 : getTargetInstanceId().hashCode());
        result = prime * result + ((getClientIp() == null) ? 0 : getClientIp().hashCode());
        result = prime * result + ((getUserAgent() == null) ? 0 : getUserAgent().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", masterId=").append(masterId);
        sb.append(", operationType=").append(operationType);
        sb.append(", operationTime=").append(operationTime);
        sb.append(", isSuccess=").append(isSuccess);
        sb.append(", detail=").append(detail);
        sb.append(", targetInstanceId=").append(targetInstanceId);
        sb.append(", clientIp=").append(clientIp);
        sb.append(", userAgent=").append(userAgent);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}