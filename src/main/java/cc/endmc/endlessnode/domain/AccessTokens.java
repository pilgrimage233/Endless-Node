package cc.endmc.endlessnode.domain;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

/**
 * @TableName access_tokens
 */
@TableName(value = "access_tokens")
@Data
public class AccessTokens implements Serializable {
    @TableField(exist = false)
    private static final long serialVersionUID = 1L;
    /**
     *
     */
    @TableId(value = "token")
    private String token;
    /**
     *
     */
    @TableField(value = "master_id")
    private Integer masterId;
    /**
     *
     */
    @TableField(value = "expires_at")
    private Date expiresAt;
    /**
     *
     */
    @TableField(value = "scope")
    private String scope;
    /**
     *
     */
    @TableField(value = "created_at")
    private Date createdAt;

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
        AccessTokens other = (AccessTokens) that;
        return (this.getToken() == null ? other.getToken() == null : this.getToken().equals(other.getToken()))
                && (this.getMasterId() == null ? other.getMasterId() == null : this.getMasterId().equals(other.getMasterId()))
                && (this.getExpiresAt() == null ? other.getExpiresAt() == null : this.getExpiresAt().equals(other.getExpiresAt()))
                && (this.getScope() == null ? other.getScope() == null : this.getScope().equals(other.getScope()))
                && (this.getCreatedAt() == null ? other.getCreatedAt() == null : this.getCreatedAt().equals(other.getCreatedAt()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getToken() == null) ? 0 : getToken().hashCode());
        result = prime * result + ((getMasterId() == null) ? 0 : getMasterId().hashCode());
        result = prime * result + ((getExpiresAt() == null) ? 0 : getExpiresAt().hashCode());
        result = prime * result + ((getScope() == null) ? 0 : getScope().hashCode());
        result = prime * result + ((getCreatedAt() == null) ? 0 : getCreatedAt().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", token=").append(token);
        sb.append(", masterId=").append(masterId);
        sb.append(", expiresAt=").append(expiresAt);
        sb.append(", scope=").append(scope);
        sb.append(", createdAt=").append(createdAt);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}