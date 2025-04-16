package cc.endmc.endlessnode.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import oshi.SystemInfo;
import oshi.hardware.*;
import oshi.software.os.FileSystem;
import oshi.software.os.OSFileStore;
import oshi.software.os.OperatingSystem;
import oshi.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/system")
@RequiredArgsConstructor
public class SystemController {

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
} 