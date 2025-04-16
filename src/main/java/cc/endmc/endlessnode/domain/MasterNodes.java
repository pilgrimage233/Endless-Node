package cc.endmc.endlessnode.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

/**
 * @TableName master_nodes
 */
@TableName(value = "master_nodes")
@Data
public class MasterNodes implements Serializable {
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
    @TableField(value = "uuid")
    private String uuid;
    /**
     * 主控端版本
     */
    @TableField(value = "version")
    private String version;
    /**
     * 节点端生成的永久token
     */
    @TableField(value = "secret_key")
    private String secretKey;
    /**
     *
     */
    @TableField(value = "ip_address")
    private String ipAddress;
    /**
     *
     */
    @TableField(value = "registered_at")
    private Date registeredAt;
    /**
     *
     */
    @TableField(value = "last_communication")
    private Date lastCommunication;
    /**
     *
     */
    @TableField(value = "is_deleted")
    private Integer isDeleted;
    /**
     *
     */
    @TableField(value = "protocol_version")
    private String protocolVersion;

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
        MasterNodes other = (MasterNodes) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
                && (this.getUuid() == null ? other.getUuid() == null : this.getUuid().equals(other.getUuid()))
                && (this.getVersion() == null ? other.getVersion() == null : this.getVersion().equals(other.getVersion()))
                && (this.getSecretKey() == null ? other.getSecretKey() == null : this.getSecretKey().equals(other.getSecretKey()))
                && (this.getIpAddress() == null ? other.getIpAddress() == null : this.getIpAddress().equals(other.getIpAddress()))
                && (this.getRegisteredAt() == null ? other.getRegisteredAt() == null : this.getRegisteredAt().equals(other.getRegisteredAt()))
                && (this.getLastCommunication() == null ? other.getLastCommunication() == null : this.getLastCommunication().equals(other.getLastCommunication()))
                && (this.getIsDeleted() == null ? other.getIsDeleted() == null : this.getIsDeleted().equals(other.getIsDeleted()))
                && (this.getProtocolVersion() == null ? other.getProtocolVersion() == null : this.getProtocolVersion().equals(other.getProtocolVersion()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getUuid() == null) ? 0 : getUuid().hashCode());
        result = prime * result + ((getVersion() == null) ? 0 : getVersion().hashCode());
        result = prime * result + ((getSecretKey() == null) ? 0 : getSecretKey().hashCode());
        result = prime * result + ((getIpAddress() == null) ? 0 : getIpAddress().hashCode());
        result = prime * result + ((getRegisteredAt() == null) ? 0 : getRegisteredAt().hashCode());
        result = prime * result + ((getLastCommunication() == null) ? 0 : getLastCommunication().hashCode());
        result = prime * result + ((getIsDeleted() == null) ? 0 : getIsDeleted().hashCode());
        result = prime * result + ((getProtocolVersion() == null) ? 0 : getProtocolVersion().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", uuid=").append(uuid);
        sb.append(", version=").append(version);
        sb.append(", secretKey=").append(secretKey);
        sb.append(", ipAddress=").append(ipAddress);
        sb.append(", registeredAt=").append(registeredAt);
        sb.append(", lastCommunication=").append(lastCommunication);
        sb.append(", isDeleted=").append(isDeleted);
        sb.append(", protocolVersion=").append(protocolVersion);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}