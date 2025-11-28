package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.domain.MasterNodes;
import cc.endmc.endlessnode.dto.HeartbeatResponse;
import cc.endmc.endlessnode.dto.MasterNodeUpdateRequest;
import cc.endmc.endlessnode.service.MasterNodesService;
import cc.endmc.endlessnode.service.ServerInstancesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import oshi.SystemInfo;
import oshi.hardware.*;
import oshi.software.os.FileSystem;
import oshi.software.os.OSFileStore;
import oshi.software.os.OperatingSystem;
import oshi.util.Util;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/system")
@RequiredArgsConstructor
public class SystemController {

    private final ServerInstancesService serverInstancesService;
    private final MasterNodesService masterNodesService;

    @Value("${node.version}")
    private String nodeVersion;

    /**
     * 获取系统基本信息
     *
     * @return 系统基本信息
     */
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getSystemInfo() {
        SystemInfo systemInfo = new SystemInfo();
        OperatingSystem operatingSystem = systemInfo.getOperatingSystem();

        Map<String, Object> response = new HashMap<>();

        // 操作系统信息
        response.put("os", getOSInfo(operatingSystem));

        response.put("success", true);

        return ResponseEntity.ok(response);
    }

    /**
     * 获取系统硬件信息
     *
     * @return 系统硬件信息
     */
    @GetMapping("/hardware")
    public ResponseEntity<Map<String, Object>> getHardwareInfo() {
        SystemInfo systemInfo = new SystemInfo();
        HardwareAbstractionLayer hardware = systemInfo.getHardware();
        OperatingSystem operatingSystem = systemInfo.getOperatingSystem();

        Map<String, Object> response = new HashMap<>();

        // CPU信息
        response.put("cpu", getCPUInfo(hardware.getProcessor()));

        // 内存信息
        response.put("memory", getMemoryInfo(hardware.getMemory()));

        // 硬盘信息
        response.put("disks", getDiskInfo(operatingSystem.getFileSystem()));

        // 网络信息
        response.put("network", getNetworkInfo(hardware.getNetworkIFs().toArray(new NetworkIF[0])));

        response.put("os", getOSInfo(operatingSystem));

        response.put("success", true);

        return ResponseEntity.ok(response);
    }

    /**
     * 获取系统负载信息
     *
     * @return 系统负载信息
     */
    @GetMapping("/load")
    public ResponseEntity<Map<String, Object>> getSystemLoad() {
        SystemInfo systemInfo = new SystemInfo();
        HardwareAbstractionLayer hardware = systemInfo.getHardware();

        Map<String, Object> response = new HashMap<>();

        // 系统负载
        response.put("load", getSystemLoad(hardware));

        response.put("success", true);

        return ResponseEntity.ok(response);
    }

    /**
     * 获取操作系统信息
     *
     * @param os 操作系统
     * @return 操作系统信息
     */
    private Map<String, Object> getOSInfo(OperatingSystem os) {
        Map<String, Object> osInfo = new HashMap<>();
        osInfo.put("family", os.getFamily());
        osInfo.put("manufacturer", os.getManufacturer());
        osInfo.put("name", os.getFamily() + " " + os.getVersionInfo().getVersion());
        osInfo.put("version", os.getVersionInfo().toString());
        osInfo.put("buildNumber", os.getVersionInfo().getBuildNumber());
        osInfo.put("bitness", os.getBitness());
        osInfo.put("bootTime", os.getSystemBootTime());
        osInfo.put("uptime", os.getSystemUptime());
        return osInfo;
    }

    /**
     * 获取CPU信息
     *
     * @param processor CPU处理器
     * @return CPU信息
     */
    private Map<String, Object> getCPUInfo(CentralProcessor processor) {
        Map<String, Object> cpuInfo = new HashMap<>();

        // 基本信息
        cpuInfo.put("name", processor.getProcessorIdentifier().getName());
        cpuInfo.put("vendor", processor.getProcessorIdentifier().getVendor());
        cpuInfo.put("vendorFreq", processor.getProcessorIdentifier().getVendorFreq());
        cpuInfo.put("family", processor.getProcessorIdentifier().getFamily());
        cpuInfo.put("model", processor.getProcessorIdentifier().getModel());
        cpuInfo.put("stepping", processor.getProcessorIdentifier().getStepping());
        cpuInfo.put("microarchitecture", processor.getProcessorIdentifier().getMicroarchitecture());
        cpuInfo.put("identifier", processor.getProcessorIdentifier().getIdentifier());
        cpuInfo.put("is64bit", processor.getProcessorIdentifier().isCpu64bit());
        cpuInfo.put("physicalProcessorCount", processor.getPhysicalProcessorCount());
        cpuInfo.put("logicalProcessorCount", processor.getLogicalProcessorCount());
        cpuInfo.put("physicalPackageCount", processor.getPhysicalPackageCount());

        // CPU使用率
        long[] prevTicks = processor.getSystemCpuLoadTicks();
        Util.sleep(1000);
        long[] ticks = processor.getSystemCpuLoadTicks();

        long user = ticks[CentralProcessor.TickType.USER.getIndex()] - prevTicks[CentralProcessor.TickType.USER.getIndex()];
        long nice = ticks[CentralProcessor.TickType.NICE.getIndex()] - prevTicks[CentralProcessor.TickType.NICE.getIndex()];
        long sys = ticks[CentralProcessor.TickType.SYSTEM.getIndex()] - prevTicks[CentralProcessor.TickType.SYSTEM.getIndex()];
        long idle = ticks[CentralProcessor.TickType.IDLE.getIndex()] - prevTicks[CentralProcessor.TickType.IDLE.getIndex()];
        long iowait = ticks[CentralProcessor.TickType.IOWAIT.getIndex()] - prevTicks[CentralProcessor.TickType.IOWAIT.getIndex()];
        long irq = ticks[CentralProcessor.TickType.IRQ.getIndex()] - prevTicks[CentralProcessor.TickType.IRQ.getIndex()];
        long softirq = ticks[CentralProcessor.TickType.SOFTIRQ.getIndex()] - prevTicks[CentralProcessor.TickType.SOFTIRQ.getIndex()];
        long steal = ticks[CentralProcessor.TickType.STEAL.getIndex()] - prevTicks[CentralProcessor.TickType.STEAL.getIndex()];
        long totalCpu = user + nice + sys + idle + iowait + irq + softirq + steal;

        Map<String, Object> cpuLoad = new HashMap<>();
        cpuLoad.put("user", user * 100.0 / totalCpu);
        cpuLoad.put("nice", nice * 100.0 / totalCpu);
        cpuLoad.put("system", sys * 100.0 / totalCpu);
        cpuLoad.put("idle", idle * 100.0 / totalCpu);
        cpuLoad.put("iowait", iowait * 100.0 / totalCpu);
        cpuLoad.put("irq", irq * 100.0 / totalCpu);
        cpuLoad.put("softirq", softirq * 100.0 / totalCpu);
        cpuLoad.put("steal", steal * 100.0 / totalCpu);
        cpuLoad.put("total", 100.0 - (idle * 100.0 / totalCpu));

        cpuInfo.put("load", cpuLoad);

        // 每个核心的使用率
        long[][] prevTicksPerCore = processor.getProcessorCpuLoadTicks();
        Util.sleep(1000);
        long[][] ticksPerCore = processor.getProcessorCpuLoadTicks();

        List<Map<String, Object>> perCoreLoad = new ArrayList<>();
        for (int i = 0; i < processor.getLogicalProcessorCount(); i++) {
            Map<String, Object> coreLoad = new HashMap<>();
            long userCore = ticksPerCore[i][CentralProcessor.TickType.USER.getIndex()] -
                    prevTicksPerCore[i][CentralProcessor.TickType.USER.getIndex()];
            long niceCore = ticksPerCore[i][CentralProcessor.TickType.NICE.getIndex()] -
                    prevTicksPerCore[i][CentralProcessor.TickType.NICE.getIndex()];
            long sysCore = ticksPerCore[i][CentralProcessor.TickType.SYSTEM.getIndex()] -
                    prevTicksPerCore[i][CentralProcessor.TickType.SYSTEM.getIndex()];
            long idleCore = ticksPerCore[i][CentralProcessor.TickType.IDLE.getIndex()] -
                    prevTicksPerCore[i][CentralProcessor.TickType.IDLE.getIndex()];
            long totalCore = userCore + niceCore + sysCore + idleCore;

            coreLoad.put("core", i);
            coreLoad.put("user", userCore * 100.0 / totalCore);
            coreLoad.put("nice", niceCore * 100.0 / totalCore);
            coreLoad.put("system", sysCore * 100.0 / totalCore);
            coreLoad.put("idle", idleCore * 100.0 / totalCore);
            coreLoad.put("total", 100.0 - (idleCore * 100.0 / totalCore));

            perCoreLoad.add(coreLoad);
        }

        cpuInfo.put("perCoreLoad", perCoreLoad);

        return cpuInfo;
    }

    /**
     * 获取内存信息
     *
     * @param memory 内存
     * @return 内存信息
     */
    private Map<String, Object> getMemoryInfo(GlobalMemory memory) {
        Map<String, Object> memoryInfo = new HashMap<>();

        // 物理内存
        Map<String, Object> physicalMemory = new HashMap<>();
        physicalMemory.put("total", memory.getTotal());
        physicalMemory.put("available", memory.getAvailable());
        physicalMemory.put("used", memory.getTotal() - memory.getAvailable());
        physicalMemory.put("usedPercent", (memory.getTotal() - memory.getAvailable()) * 100.0 / memory.getTotal());

        // 虚拟内存
        VirtualMemory virtualMemory = memory.getVirtualMemory();
        Map<String, Object> swapMemory = new HashMap<>();
        swapMemory.put("total", virtualMemory.getSwapTotal());
        swapMemory.put("used", virtualMemory.getSwapUsed());
        swapMemory.put("usedPercent", virtualMemory.getSwapUsed() * 100.0 / virtualMemory.getSwapTotal());

        memoryInfo.put("physical", physicalMemory);
        memoryInfo.put("swap", swapMemory);

        return memoryInfo;
    }

    /**
     * 获取硬盘信息
     *
     * @param fileSystem 文件系统
     * @return 硬盘信息
     */
    private List<Map<String, Object>> getDiskInfo(FileSystem fileSystem) {
        List<Map<String, Object>> diskInfoList = new ArrayList<>();

        for (OSFileStore store : fileSystem.getFileStores()) {
            Map<String, Object> diskInfo = new HashMap<>();
            diskInfo.put("name", store.getName());
            diskInfo.put("mount", store.getMount());
            diskInfo.put("description", store.getDescription());
            diskInfo.put("type", store.getType());
            diskInfo.put("uuid", store.getUUID());
            diskInfo.put("total", store.getTotalSpace());
            diskInfo.put("usable", store.getUsableSpace());
            diskInfo.put("used", store.getTotalSpace() - store.getUsableSpace());
            diskInfo.put("usedPercent", (store.getTotalSpace() - store.getUsableSpace()) * 100.0 / store.getTotalSpace());

            diskInfoList.add(diskInfo);
        }

        return diskInfoList;
    }

    /**
     * 获取网络信息
     *
     * @param networkIFs 网络接口
     * @return 网络信息
     */
    private List<Map<String, Object>> getNetworkInfo(NetworkIF[] networkIFs) {
        List<Map<String, Object>> networkInfoList = new ArrayList<>();

        for (NetworkIF net : networkIFs) {
            Map<String, Object> networkInfo = new HashMap<>();
            networkInfo.put("name", net.getName());
            networkInfo.put("displayName", net.getDisplayName());
            networkInfo.put("mac", net.getMacaddr());
            networkInfo.put("ipv4", net.getIPv4addr());
            networkInfo.put("ipv6", net.getIPv6addr());
            networkInfo.put("mtu", net.getMTU());
            networkInfo.put("speed", net.getSpeed());
            networkInfo.put("bytesRecv", net.getBytesRecv());
            networkInfo.put("bytesSent", net.getBytesSent());
            networkInfo.put("packetsRecv", net.getPacketsRecv());
            networkInfo.put("packetsSent", net.getPacketsSent());
            networkInfo.put("inErrors", net.getInErrors());
            networkInfo.put("outErrors", net.getOutErrors());
            networkInfo.put("inDrops", net.getInDrops());
            networkInfo.put("collisions", net.getCollisions());

            networkInfoList.add(networkInfo);
        }

        return networkInfoList;
    }

    /**
     * 获取系统负载
     *
     * @param hardware 硬件抽象层
     * @return 系统负载
     */
    private Map<String, Object> getSystemLoad(HardwareAbstractionLayer hardware) {
        Map<String, Object> loadInfo = new HashMap<>();

        // CPU负载
        CentralProcessor processor = hardware.getProcessor();
        long[] prevTicks = processor.getSystemCpuLoadTicks();
        Util.sleep(1000);
        long[] ticks = processor.getSystemCpuLoadTicks();
        long user = ticks[CentralProcessor.TickType.USER.getIndex()] - prevTicks[CentralProcessor.TickType.USER.getIndex()];
        long nice = ticks[CentralProcessor.TickType.NICE.getIndex()] - prevTicks[CentralProcessor.TickType.NICE.getIndex()];
        long sys = ticks[CentralProcessor.TickType.SYSTEM.getIndex()] - prevTicks[CentralProcessor.TickType.SYSTEM.getIndex()];
        long idle = ticks[CentralProcessor.TickType.IDLE.getIndex()] - prevTicks[CentralProcessor.TickType.IDLE.getIndex()];
        long iowait = ticks[CentralProcessor.TickType.IOWAIT.getIndex()] - prevTicks[CentralProcessor.TickType.IOWAIT.getIndex()];
        long irq = ticks[CentralProcessor.TickType.IRQ.getIndex()] - prevTicks[CentralProcessor.TickType.IRQ.getIndex()];
        long softirq = ticks[CentralProcessor.TickType.SOFTIRQ.getIndex()] - prevTicks[CentralProcessor.TickType.SOFTIRQ.getIndex()];
        long steal = ticks[CentralProcessor.TickType.STEAL.getIndex()] - prevTicks[CentralProcessor.TickType.STEAL.getIndex()];
        long totalCpu = user + nice + sys + idle + iowait + irq + softirq + steal;
        double cpuLoad = totalCpu == 0 ? 0 : 100d * (totalCpu - idle) / totalCpu;

        // CPU详细负载信息
        Map<String, Object> cpuLoadDetail = new HashMap<>();
        cpuLoadDetail.put("user", user * 100.0 / totalCpu);
        cpuLoadDetail.put("nice", nice * 100.0 / totalCpu);
        cpuLoadDetail.put("system", sys * 100.0 / totalCpu);
        cpuLoadDetail.put("idle", idle * 100.0 / totalCpu);
        cpuLoadDetail.put("iowait", iowait * 100.0 / totalCpu);
        cpuLoadDetail.put("irq", irq * 100.0 / totalCpu);
        cpuLoadDetail.put("softirq", softirq * 100.0 / totalCpu);
        cpuLoadDetail.put("steal", steal * 100.0 / totalCpu);

        // 内存负载
        GlobalMemory memory = hardware.getMemory();
        double memoryLoad = (memory.getTotal() - memory.getAvailable()) * 100.0 / memory.getTotal();

        // 网络流量统计
        NetworkIF[] networkIFs = hardware.getNetworkIFs().toArray(new NetworkIF[0]);

        // 第一次采样
        long prevBytesRecv = 0;
        long prevBytesSent = 0;
        long totalBytesRecv = 0;
        long totalBytesSent = 0;

        for (NetworkIF net : networkIFs) {
            net.updateAttributes();
            // 当前接收和发送的字节数
            prevBytesRecv += net.getBytesRecv();
            prevBytesSent += net.getBytesSent();

            // 累加总接收和发送字节数
            totalBytesRecv += net.getBytesRecv();
            totalBytesSent += net.getBytesSent();
        }

        // 等待1秒
        Util.sleep(1000);

        // 第二次采样
        long currBytesRecv = 0;
        long currBytesSent = 0;

        for (NetworkIF net : networkIFs) {
            net.updateAttributes();
            currBytesRecv += net.getBytesRecv();
            currBytesSent += net.getBytesSent();
        }

        // 计算每秒的差值
        long bytesRecvPerSec = currBytesRecv - prevBytesRecv;
        long bytesSentPerSec = currBytesSent - prevBytesSent;

        // 整合所有负载信息
        Map<String, Object> cpu = new HashMap<>();
        cpu.put("load", cpuLoad);
        cpu.put("loadDetail", cpuLoadDetail);
        loadInfo.put("cpu", cpu);

        loadInfo.put("memoryLoad", memoryLoad);

        Map<String, Object> network = new HashMap<>();
        network.put("bytesRecvPerSec", bytesRecvPerSec);
        network.put("bytesSentPerSec", bytesSentPerSec);
        network.put("totalBytesRecv", totalBytesRecv);  // 总接收字节数
        network.put("totalBytesSent", totalBytesSent);  // 总发送字节数
        loadInfo.put("network", network);

        return loadInfo;
    }

    /**
     * 测试连接接口
     * 主控端调用此接口测试与节点的连接
     *
     * @return 测试结果
     */
    @GetMapping("/test-connection")
    public ResponseEntity<Map<String, Object>> testConnection() {
        Map<String, Object> response = new HashMap<>();

        try {
            response.put("success", true);
            response.put("message", "连接成功");
            response.put("version", nodeVersion);
            response.put("timestamp", new Date());
            response.put("status", "ONLINE");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "连接测试失败: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * 心跳检测接口
     * 主控端调用此接口获取节点状态信息
     *
     * @return 心跳响应信息
     */
    @GetMapping("/heartbeat")
    public ResponseEntity<HeartbeatResponse> heartbeat() {
        HeartbeatResponse response = new HeartbeatResponse();

        // 设置基本状态信息
        response.setStatus("OJBK");
        response.setVersion(nodeVersion); // 可以从配置文件读取
        response.setProtocolVersion("1.0");
        response.setTimestamp(new Date());

        // 获取JVM运行时间
        RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
        response.setUptime(runtimeBean.getUptime());

        // 获取系统信息
        response.setSystemInfo(getHeartbeatSystemInfo());

        // 获取服务器实例统计
        response.setServerStats(getServerStats());

        // 获取系统负载信息
        response.setSystemLoad(getSystemLoad(new SystemInfo().getHardware()));

        return ResponseEntity.ok(response);
    }

    /**
     * 获取心跳检测用的系统基本信息
     *
     * @return 系统信息
     */
    private HeartbeatResponse.SystemInfo getHeartbeatSystemInfo() {
        HeartbeatResponse.SystemInfo systemInfo = new HeartbeatResponse.SystemInfo();

        // 操作系统信息
        OperatingSystem os = new SystemInfo().getOperatingSystem();
        systemInfo.setOsName(os.getFamily() + " " + os.getVersionInfo().getVersion());
        systemInfo.setOsVersion(os.getVersionInfo().toString());
        systemInfo.setArchitecture(System.getProperty("os.arch"));

        // Java信息
        systemInfo.setJavaVersion(System.getProperty("java.version"));
        systemInfo.setAvailableProcessors(Runtime.getRuntime().availableProcessors());

        // 内存信息
        systemInfo.setTotalMemory(Runtime.getRuntime().totalMemory());
        systemInfo.setFreeMemory(Runtime.getRuntime().freeMemory());
        systemInfo.setMaxMemory(Runtime.getRuntime().maxMemory());

        return systemInfo;
    }

    /**
     * 获取服务器实例统计信息
     *
     * @return 服务器统计信息
     */
    private HeartbeatResponse.ServerStats getServerStats() {
        HeartbeatResponse.ServerStats stats = new HeartbeatResponse.ServerStats();

        // 获取所有服务器实例
        List<cc.endmc.endlessnode.domain.ServerInstances> allInstances = serverInstancesService.list();

        stats.setTotalInstances(allInstances.size());

        // 统计运行状态
        long runningCount = allInstances.stream()
                .filter(instance -> "RUNNING".equals(instance.getStatus()))
                .count();
        stats.setRunningInstances((int) runningCount);
        stats.setStoppedInstances(allInstances.size() - (int) runningCount);

        // 计算总分配内存
        int totalMemory = allInstances.stream()
                .mapToInt(instance -> instance.getMemoryMb() != null ? instance.getMemoryMb() : 0)
                .sum();
        stats.setTotalAllocatedMemory(totalMemory);

        // 构建实例信息列表
        List<HeartbeatResponse.InstanceInfo> instanceInfos = allInstances.stream()
                .map(this::convertToInstanceInfo)
                .collect(Collectors.toList());
        stats.setInstances(instanceInfos);

        return stats;
    }

    /**
     * 转换服务器实例为实例信息
     *
     * @param instance 服务器实例
     * @return 实例信息
     */
    private HeartbeatResponse.InstanceInfo convertToInstanceInfo(cc.endmc.endlessnode.domain.ServerInstances instance) {
        HeartbeatResponse.InstanceInfo info = new HeartbeatResponse.InstanceInfo();
        info.setId(instance.getId());
        info.setName(instance.getInstanceName());
        info.setStatus(instance.getStatus());
        info.setPort(instance.getPort());
        info.setMemoryMb(instance.getMemoryMb());
        info.setCoreType(instance.getCoreType());
        info.setVersion(instance.getVersion());
        return info;
    }

    /**
     * 最后通信回调接口
     * 主控端调用此接口更新最后通信时间
     *
     * @param masterUuid 主控端UUID
     * @return 更新结果
     */
    @GetMapping("/communication-callback")
    public ResponseEntity<Map<String, Object>> communicationCallback(@RequestParam String masterUuid) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 验证参数
            if (masterUuid == null || masterUuid.trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "主控端UUID不能为空");
                return ResponseEntity.badRequest().body(response);
            }

            // 查找对应的主控端记录
            List<MasterNodes> masterNodes = masterNodesService.list();
            MasterNodes targetMaster = null;

            for (MasterNodes master : masterNodes) {
                if (masterUuid.equals(master.getUuid())) {
                    targetMaster = master;
                    break;
                }
            }

            if (targetMaster == null) {
                response.put("success", false);
                response.put("message", "未找到对应的主控端记录");
                return ResponseEntity.notFound().build();
            }

            // 更新最后通信时间
            targetMaster.setLastCommunication(new Date());
            boolean updateResult = masterNodesService.updateById(targetMaster);

            if (updateResult) {
                response.put("success", true);
                response.put("message", "最后通信时间更新成功");
                response.put("lastCommunication", targetMaster.getLastCommunication());
            } else {
                response.put("success", false);
                response.put("message", "最后通信时间更新失败");
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "更新最后通信时间时发生错误: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * 最后通信回调接口（带IP地址）
     * 主控端调用此接口更新最后通信时间和IP地址
     *
     * @param masterUuid 主控端UUID
     * @param ipAddress  主控端IP地址（可选）
     * @return 更新结果
     */
    @GetMapping("/communication-callback-with-ip/{masterUuid}/{ipAddress}")
    public ResponseEntity<Map<String, Object>> communicationCallbackWithIp(
            @PathVariable String masterUuid,
            @PathVariable(required = false) String ipAddress) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 验证参数
            if (masterUuid == null || masterUuid.trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "主控端UUID不能为空");
                return ResponseEntity.badRequest().body(response);
            }

            // 查找对应的主控端记录
            List<MasterNodes> masterNodes = masterNodesService.list();
            MasterNodes targetMaster = null;

            for (MasterNodes master : masterNodes) {
                if (masterUuid.equals(master.getUuid())) {
                    targetMaster = master;
                    break;
                }
            }

            if (targetMaster == null) {
                response.put("success", false);
                response.put("message", "未找到对应的主控端记录");
                return ResponseEntity.notFound().build();
            }

            // 更新最后通信时间和IP地址
            targetMaster.setLastCommunication(new Date());
            if (ipAddress != null && !ipAddress.trim().isEmpty()) {
                targetMaster.setIpAddress(ipAddress);
            }

            boolean updateResult = masterNodesService.updateById(targetMaster);

            if (updateResult) {
                response.put("success", true);
                response.put("message", "最后通信时间和IP地址更新成功");
                response.put("lastCommunication", targetMaster.getLastCommunication());
                response.put("ipAddress", targetMaster.getIpAddress());
            } else {
                response.put("success", false);
                response.put("message", "最后通信时间和IP地址更新失败");
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "更新最后通信时间时发生错误: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * 主控端信息更新接口
     * 主控端首次启动或信息变更时调用此接口更新主控端信息
     *
     * @param request 主控端信息更新请求
     * @return 更新结果
     */
    @PostMapping("/master-info-update")
    public ResponseEntity<Map<String, Object>> updateMasterInfo(@RequestBody MasterNodeUpdateRequest request) {
        Map<String, Object> response = new HashMap<>();

        try {
            // 验证参数
            if (request.getMasterUuid() == null || request.getMasterUuid().trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "主控端UUID不能为空");
                return ResponseEntity.badRequest().body(response);
            }

            // 查找对应的主控端记录
            List<MasterNodes> masterNodes = masterNodesService.list();
            MasterNodes targetMaster = null;

            for (MasterNodes master : masterNodes) {
                if (request.getMasterUuid().equals(master.getUuid())) {
                    targetMaster = master;
                    break;
                }
            }

            if (targetMaster == null) {
                response.put("success", false);
                response.put("message", "未找到对应的主控端记录");
                return ResponseEntity.notFound().build();
            }

            // 更新主控端信息
            boolean hasUpdate = false;

            // 更新版本号
            if (request.getVersion() != null && !request.getVersion().trim().isEmpty()) {
                targetMaster.setVersion(request.getVersion());
                hasUpdate = true;
            }

            // 更新协议版本
            if (request.getProtocolVersion() != null && !request.getProtocolVersion().trim().isEmpty()) {
                targetMaster.setProtocolVersion(request.getProtocolVersion());
                hasUpdate = true;
            }

            // 更新IP地址
            if (request.getIpAddress() != null && !request.getIpAddress().trim().isEmpty()) {
                targetMaster.setIpAddress(request.getIpAddress());
                hasUpdate = true;
            }

            // 更新最后通信时间
            targetMaster.setLastCommunication(new Date());
            hasUpdate = true;

            if (!hasUpdate) {
                response.put("success", false);
                response.put("message", "没有需要更新的信息");
                return ResponseEntity.badRequest().body(response);
            }

            // 执行数据库更新
            boolean updateResult = masterNodesService.updateById(targetMaster);

            if (updateResult) {
                response.put("success", true);
                response.put("message", "主控端信息更新成功");
                response.put("updatedFields", getUpdatedFields(request));
                response.put("lastCommunication", targetMaster.getLastCommunication());
            } else {
                response.put("success", false);
                response.put("message", "主控端信息更新失败");
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "更新主控端信息时发生错误: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * 获取更新的字段列表
     *
     * @param request 更新请求
     * @return 更新的字段列表
     */
    private List<String> getUpdatedFields(MasterNodeUpdateRequest request) {
        List<String> updatedFields = new ArrayList<>();

        if (request.getVersion() != null && !request.getVersion().trim().isEmpty()) {
            updatedFields.add("version");
        }
        if (request.getProtocolVersion() != null && !request.getProtocolVersion().trim().isEmpty()) {
            updatedFields.add("protocolVersion");
        }
        if (request.getIpAddress() != null && !request.getIpAddress().trim().isEmpty()) {
            updatedFields.add("ipAddress");
        }
        updatedFields.add("lastCommunication");

        return updatedFields;
    }

    /**
     * 主控端信息更新接口（简化版，使用URL参数）
     * 主控端首次启动时调用此接口更新基本信息
     *
     * @param masterUuid      主控端UUID
     * @param version         主控端版本号
     * @param protocolVersion 协议版本
     * @param ipAddress       主控端IP地址
     * @return 更新结果
     */
    @GetMapping("/master-info-update-simple")
    public ResponseEntity<Map<String, Object>> updateMasterInfoSimple(
            @RequestParam String masterUuid,
            @RequestParam(required = false) String version,
            @RequestParam(required = false) String protocolVersion,
            @RequestParam(required = false) String ipAddress) {

        Map<String, Object> response = new HashMap<>();

        try {
            // 验证参数
            if (masterUuid == null || masterUuid.trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "主控端UUID不能为空");
                return ResponseEntity.badRequest().body(response);
            }

            // 查找对应的主控端记录
            List<MasterNodes> masterNodes = masterNodesService.list();
            MasterNodes targetMaster = null;

            for (MasterNodes master : masterNodes) {
                if (masterUuid.equals(master.getUuid())) {
                    targetMaster = master;
                    break;
                }
            }

            if (targetMaster == null) {
                response.put("success", false);
                response.put("message", "未找到对应的主控端记录");
                return ResponseEntity.notFound().build();
            }

            // 更新主控端信息
            boolean hasUpdate = false;

            // 更新版本号
            if (version != null && !version.trim().isEmpty()) {
                targetMaster.setVersion(version);
                hasUpdate = true;
            }

            // 更新协议版本
            if (protocolVersion != null && !protocolVersion.trim().isEmpty()) {
                targetMaster.setProtocolVersion(protocolVersion);
                hasUpdate = true;
            }

            // 更新IP地址
            if (ipAddress != null && !ipAddress.trim().isEmpty()) {
                targetMaster.setIpAddress(ipAddress);
                hasUpdate = true;
            }

            // 更新最后通信时间
            targetMaster.setLastCommunication(new Date());
            hasUpdate = true;

            if (!hasUpdate) {
                response.put("success", false);
                response.put("message", "没有需要更新的信息");
                return ResponseEntity.badRequest().body(response);
            }

            // 执行数据库更新
            boolean updateResult = masterNodesService.updateById(targetMaster);

            if (updateResult) {
                response.put("success", true);
                response.put("message", "主控端信息更新成功");
                response.put("version", targetMaster.getVersion());
                response.put("protocolVersion", targetMaster.getProtocolVersion());
                response.put("ipAddress", targetMaster.getIpAddress());
                response.put("lastCommunication", targetMaster.getLastCommunication());
                log.info("主控端信息更新成功: UUID={}, Version={}, ProtocolVersion={}, IP={}",
                        masterUuid, targetMaster.getVersion(),
                        targetMaster.getProtocolVersion(),
                        targetMaster.getIpAddress());

            } else {
                response.put("success", false);
                response.put("message", "主控端信息更新失败");
                log.warn("主控端信息更新失败: UUID={}", masterUuid);
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "更新主控端信息时发生错误: " + e.getMessage());
            log.error(e.getMessage(), e);
            return ResponseEntity.internalServerError().body(response);
        }
    }
} 