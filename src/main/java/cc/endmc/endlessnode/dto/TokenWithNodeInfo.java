package cc.endmc.endlessnode.dto;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.MasterNodes;
import lombok.Data;

import java.util.Date;

/**
 * Token与节点信息关联的DTO
 */
@Data
public class TokenWithNodeInfo {

    // Token信息
    private String token;
    private Integer masterId;
    private Date expiresAt;
    private String scope;
    private String remark;
    private Date createdAt;

    // 节点信息（如果已绑定）
    private String nodeUuid;
    private String nodeVersion;
    private String nodeIpAddress;
    private Date nodeRegisteredAt;
    private Date nodeLastCommunication;
    private Integer nodeIsDeleted;
    private String nodeProtocolVersion;

    // 绑定状态
    private Boolean isBound;
    private String nodeStatus; // ONLINE, OFFLINE, DELETED

    public TokenWithNodeInfo() {
    }

    public TokenWithNodeInfo(AccessTokens accessToken, MasterNodes masterNode) {
        // 复制Token信息
        this.token = accessToken.getToken();
        this.masterId = accessToken.getMasterId();
        this.expiresAt = accessToken.getExpiresAt();
        this.scope = accessToken.getScope();
        this.remark = accessToken.getRemark();
        this.createdAt = accessToken.getCreatedAt();

        // 复制节点信息
        if (masterNode != null) {
            this.nodeUuid = masterNode.getUuid();
            this.nodeVersion = masterNode.getVersion();
            this.nodeIpAddress = masterNode.getIpAddress();
            this.nodeRegisteredAt = masterNode.getRegisteredAt();
            this.nodeLastCommunication = masterNode.getLastCommunication();
            this.nodeIsDeleted = masterNode.getIsDeleted();
            this.nodeProtocolVersion = masterNode.getProtocolVersion();
            this.isBound = true;

            // 判断节点状态
            if (masterNode.getIsDeleted() != null && masterNode.getIsDeleted() == 1) {
                this.nodeStatus = "DELETED";
            } else if (masterNode.getLastCommunication() != null) {
                // 如果最后通信时间超过10分钟，认为离线
                long timeDiff = System.currentTimeMillis() - masterNode.getLastCommunication().getTime();
                if (timeDiff > 10 * 60 * 1000) {
                    this.nodeStatus = "OFFLINE";
                } else {
                    this.nodeStatus = "ONLINE";
                }
            } else {
                this.nodeStatus = "OFFLINE";
            }
        } else {
            this.isBound = false;
            this.nodeStatus = "UNBOUND";
        }
    }
}
