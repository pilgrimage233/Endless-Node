package cc.endmc.endlessnode.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.*;

/**
 * 服务器模板：一键部署预设模板，自动下载核心 JAR、生成配置。
 */
@Slf4j
@Service
public class TemplateService {

    private final ServerInstancesService serverInstancesService;

    @Value("${endless.files.root:.}")
    private String filesRoot;

    public TemplateService(ServerInstancesService serverInstancesService) {
        this.serverInstancesService = serverInstancesService;
    }

    /**
     * 获取模板信息
     */
    public TemplateInfo getTemplate(String templateName) {
        return TEMPLATES.get(templateName);
    }

    /**
     * 部署模板：创建目录、下载核心、生成 server.properties、接受 EULA
     */
    public DeployResult deploy(String templateName, String instanceName, int memoryMb, int port, String createdBy) {
        TemplateInfo tpl = TEMPLATES.get(templateName);
        if (tpl == null) return new DeployResult(false, "未知模板: " + templateName, null);

        // 创建服务器目录
        Path serverDir = Paths.get(filesRoot, instanceName.replaceAll("[^a-zA-Z0-9_-]", "_")).toAbsolutePath().normalize();
        try {
            Files.createDirectories(serverDir);
        } catch (IOException e) {
            return new DeployResult(false, "创建目录失败: " + e.getMessage(), null);
        }

        // 接受 EULA
        try {
            Files.writeString(serverDir.resolve("eula.txt"), "eula=true\n");
        } catch (IOException e) {
            return new DeployResult(false, "写入 EULA 失败: " + e.getMessage(), null);
        }

        // 生成 server.properties
        try {
            String props = String.format("""
                    server-port=%d
                    enable-query=true
                    query.port=%d
                    gamemode=survival
                    difficulty=easy
                    max-players=20
                    online-mode=true
                    motd=%s
                    """, port, port + 1, instanceName);
            Files.writeString(serverDir.resolve("server.properties"), props);
        } catch (IOException e) {
            return new DeployResult(false, "写入 server.properties 失败: " + e.getMessage(), null);
        }

        // 下载核心 JAR
        String jarName = tpl.jarName;
        Path jarPath = serverDir.resolve(jarName);
        if (!Files.exists(jarPath)) {
            try {
                log.info("正在下载 {} 核心: {}", templateName, tpl.downloadUrl);
                downloadFile(tpl.downloadUrl, jarPath);
                log.info("核心下载完成: {}", jarPath);
            } catch (Exception e) {
                return new DeployResult(false, "下载核心失败: " + e.getMessage(), null);
            }
        }

        // 创建数据库记录
        cc.endmc.endlessnode.domain.ServerInstances instance = new cc.endmc.endlessnode.domain.ServerInstances();
        instance.setInstanceName(instanceName);
        instance.setVersion(tpl.version);
        instance.setCoreType(tpl.coreType);
        instance.setFilePath(serverDir.toString());
        instance.setPort(port);
        instance.setMemoryMb(memoryMb);
        instance.setJvmArgs("-Xmx" + memoryMb + "M -Xms" + (memoryMb / 2) + "M -XX:+UseG1GC");
        instance.setCreatedBy(createdBy);
        instance.setStatus("STOPPED");
        instance.setCreatedAt(new java.util.Date());
        serverInstancesService.save(instance);

        return new DeployResult(true, "部署成功", instance.getId());
    }

    private void downloadFile(String urlStr, Path target) throws Exception {
        URL url = new URL(urlStr);
        try (ReadableByteChannel rbc = Channels.newChannel(url.openStream());
             FileOutputStream fos = new FileOutputStream(target.toFile())) {
            fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
        }
    }

    // 模板定义
    public record TemplateInfo(String name, String version, String coreType, String jarName, String downloadUrl) {}

    public record DeployResult(boolean success, String message, Integer serverId) {}

    private static final java.util.Map<String, TemplateInfo> TEMPLATES = new java.util.HashMap<>();
    static {
        TEMPLATES.put("paper-1.20.4", new TemplateInfo("paper-1.20.4", "1.20.4", "PAPER", "paper.jar",
                "https://api.papermc.io/v2/projects/paper/versions/1.20.4/builds/496/downloads/paper-1.20.4-496.jar"));
        TEMPLATES.put("paper-1.21.4", new TemplateInfo("paper-1.21.4", "1.21.4", "PAPER", "paper.jar",
                "https://api.papermc.io/v2/projects/paper/versions/1.21.4/builds/232/downloads/paper-1.21.4-232.jar"));
        TEMPLATES.put("spigot-1.20.4", new TemplateInfo("spigot-1.20.4", "1.20.4", "SPIGOT", "spigot.jar",
                "https://download.getbukkit.org/spigot/spigot-1.20.4.jar"));
        TEMPLATES.put("vanilla-1.20.4", new TemplateInfo("vanilla-1.20.4", "1.20.4", "VANILLA", "minecraft_server.jar",
                "https://piston-data.mojang.com/v1/objects/8dd1a28015f51b1803213f0b3e5f7e0f3e0c7a0a/server.jar"));
    }
}
