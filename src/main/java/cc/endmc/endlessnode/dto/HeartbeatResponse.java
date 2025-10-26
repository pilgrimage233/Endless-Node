package cc.endmc.endlessnode.dto;

import lombok.Data;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * 心跳检测响应DTO
 * 
 * @author Memory
 */
@Data
public class HeartbeatResponse {
    
    /**
     * 节点状态
     */
    private String status;
    
    /**
     * 节点版本
     */
    private String version;
    
    /**
     * 协议版本
     */
    private String protocolVersion;
    
    /**
     * 当前时间戳
     */
    private Date timestamp;
    
    /**
     * 节点运行时间（毫秒）
     */
    private Long uptime;
    
    /**
     * 系统基本信息
     */
    private SystemInfo systemInfo;
    
    /**
     * 服务器实例统计
     */
    private ServerStats serverStats;
    
    /**
     * 系统负载信息
     */
    private Map<String, Object> systemLoad;
    
    @Data
    public static class SystemInfo {
        /**
         * 操作系统名称
         */
        private String osName;
        
        /**
         * 操作系统版本
         */
        private String osVersion;
        
        /**
         * 系统架构
         */
        private String architecture;
        
        /**
         * Java版本
         */
        private String javaVersion;
        
        /**
         * 可用处理器数量
         */
        private Integer availableProcessors;
        
        /**
         * 总内存（字节）
         */
        private Long totalMemory;
        
        /**
         * 可用内存（字节）
         */
        private Long freeMemory;
        
        /**
         * 最大内存（字节）
         */
        private Long maxMemory;
    }
    
    @Data
    public static class ServerStats {
        /**
         * 总服务器实例数
         */
        private Integer totalInstances;
        
        /**
         * 运行中的实例数
         */
        private Integer runningInstances;
        
        /**
         * 停止的实例数
         */
        private Integer stoppedInstances;
        
        /**
         * 总分配内存（MB）
         */
        private Integer totalAllocatedMemory;
        
        /**
         * 实例列表
         */
        private List<InstanceInfo> instances;
    }
    
    @Data
    public static class InstanceInfo {
        /**
         * 实例ID
         */
        private Integer id;
        
        /**
         * 实例名称
         */
        private String name;
        
        /**
         * 状态
         */
        private String status;
        
        /**
         * 端口
         */
        private Integer port;
        
        /**
         * 分配内存（MB）
         */
        private Integer memoryMb;
        
        /**
         * 核心类型
         */
        private String coreType;
        
        /**
         * 版本
         */
        private String version;
    }
}
