package cc.endmc.endlessnode.dto;

import lombok.Data;

// import javax.validation.constraints.NotBlank;

/**
 * 主控端信息更新请求DTO
 * 
 * @author Memory
 */
@Data
public class MasterNodeUpdateRequest {
    
    /**
     * 主控端UUID（必需）
     */
    // @NotBlank(message = "主控端UUID不能为空")
    private String masterUuid;
    
    /**
     * 主控端版本号
     */
    private String version;
    
    /**
     * 协议版本
     */
    private String protocolVersion;
    
    /**
     * 主控端IP地址
     */
    private String ipAddress;
    
    /**
     * 主控端名称（可选）
     */
    private String masterName;
    
    /**
     * 主控端描述（可选）
     */
    private String description;
    
    /**
     * 主控端操作系统信息（可选）
     */
    private String osInfo;
    
    /**
     * 主控端架构信息（可选）
     */
    private String architecture;
}
