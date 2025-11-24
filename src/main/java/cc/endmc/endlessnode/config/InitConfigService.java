package cc.endmc.endlessnode.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * 配置文件初始化服务
 * 在应用启动时自动生成或更新配置文件
 */
@Service
public class InitConfigService {
    private static final Logger log = LoggerFactory.getLogger(InitConfigService.class);
    private static final String CONFIG_DIR = "config";
    private static final String[] CONFIG_FILES = {
            "application.yml"
    };

    /**
     * 初始化配置文件
     * 如果配置文件不存在，则从jar包中复制
     * 如果配置文件存在，则更新node节点配置
     */
    public void initializeConfigs() {
        try {
            createConfigDirectory();
            for (String configFile : CONFIG_FILES) {
                handleApplicationYml(configFile);
            }
        } catch (Exception e) {
            log.error("配置文件初始化失败", e);
            throw new RuntimeException("配置文件初始化失败", e);
        }
    }

    /**
     * 创建配置目录
     */
    private void createConfigDirectory() throws IOException {
        Path configPath = Paths.get(CONFIG_DIR);
        if (!Files.exists(configPath)) {
            Files.createDirectory(configPath);
            log.info("创建配置目录: {}", configPath.toAbsolutePath());
        }
    }

    /**
     * 处理application.yml配置文件
     * 如果文件不存在，则创建新文件（跳过node节点）
     * 如果文件存在，则不做任何修改
     */
    private void handleApplicationYml(String configFile) throws IOException {
        Path targetPath = Paths.get(CONFIG_DIR, configFile);

        // 如果本地配置文件已存在，不做任何修改
        if (Files.exists(targetPath)) {
            log.info("配置文件已存在，跳过生成: {}", targetPath.toAbsolutePath());
            return;
        }

        // 读取jar包中的配置
        List<String> jarConfigLines;
        try (InputStream is = ResourceUtils.getURL("classpath:" + configFile).openStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            jarConfigLines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                jarConfigLines.add(line);
            }
        }

        // 过滤掉node节点，生成新的配置文件
        List<String> filteredLines = new ArrayList<>();
        boolean inNodeSection = false;
        boolean skipNextEmptyLine = false;

        for (int i = 0; i < jarConfigLines.size(); i++) {
            String line = jarConfigLines.get(i);

            // 检测到node节点开始
            if (line.trim().startsWith("node:")) {
                inNodeSection = true;
                skipNextEmptyLine = true;
                continue;
            }

            // 在node节点内部
            if (inNodeSection) {
                // 检查是否到达node节点结束
                if (!line.trim().isEmpty() && !line.startsWith(" ") && !line.startsWith("\t") && !line.startsWith("#")) {
                    inNodeSection = false;
                } else {
                    continue;
                }
            }

            // 跳过node节点后的第一个空行
            if (skipNextEmptyLine && line.trim().isEmpty()) {
                skipNextEmptyLine = false;
                continue;
            }

            // 保留非node节点的内容
            filteredLines.add(line);
        }

        // 写入文件
        Files.write(targetPath, filteredLines);
        log.info("创建新配置文件（已跳过node节点）: {}", targetPath.toAbsolutePath());
    }
}
