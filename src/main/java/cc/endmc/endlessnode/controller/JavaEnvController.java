package cc.endmc.endlessnode.controller;


import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.util.JavaDownloadUrlProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java环境管理控制器
 */
@Slf4j
@RestController
@RequestMapping("/api/java-env")
public class JavaEnvController {

    @Autowired
    private AccessTokensService accessTokensService;

    /**
     * 验证Java环境是否存在并获取版本信息
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyJavaEnv(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @RequestBody Map<String, String> request) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        String javaPath = request.get("javaPath");
        if (javaPath == null || javaPath.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Java路径不能为空"));
        }

        try {
            Map<String, Object> result = verifyAndGetJavaInfo(javaPath);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("验证Java环境失败", e);
            return ResponseEntity.status(500).body(Map.of(
                    "error", "验证Java环境失败: " + e.getMessage(),
                    "valid", false
            ));
        }
    }

    /**
     * 扫描系统中的Java环境
     */
    @GetMapping("/scan")
    public ResponseEntity<Map<String, Object>> scanJavaEnvironments(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("error", "无效的访问令牌"));
        }

        try {
            List<Map<String, Object>> environments = scanSystemJavaEnvironments();
            return ResponseEntity.ok(Map.of(
                    "environments", environments,
                    "count", environments.size()
            ));
        } catch (Exception e) {
            log.error("扫描Java环境失败", e);
            return ResponseEntity.status(500).body(Map.of("error", "扫描Java环境失败: " + e.getMessage()));
        }
    }

    /**
     * 验证并获取Java信息
     */
    private Map<String, Object> verifyAndGetJavaInfo(String javaPath) throws Exception {
        Map<String, Object> result = new HashMap<>();

        // 规范化路径
        File javaDir = new File(javaPath);
        if (!javaDir.exists()) {
            result.put("valid", false);
            result.put("error", "路径不存在");
            return result;
        }

        if (!javaDir.isDirectory()) {
            result.put("valid", false);
            result.put("error", "路径不是目录");
            return result;
        }

        // 查找java可执行文件
        String javaExecutable = findJavaExecutable(javaDir);
        if (javaExecutable == null) {
            result.put("valid", false);
            result.put("error", "未找到java可执行文件");
            return result;
        }

        // 获取Java版本信息
        Map<String, String> versionInfo = getJavaVersion(javaExecutable);
        if (versionInfo == null || versionInfo.isEmpty()) {
            result.put("valid", false);
            result.put("error", "无法获取Java版本信息");
            return result;
        }

        // 检测是JDK还是JRE（通过检查javac是否存在）
        String type = detectJavaType(javaDir);

        // 构建返回结果
        result.put("valid", true);
        result.put("version", versionInfo.get("version"));
        result.put("fullVersion", versionInfo.get("fullVersion"));
        result.put("vendor", versionInfo.get("vendor"));
        result.put("arch", versionInfo.get("arch"));
        result.put("type", type);
        result.put("javaHome", javaDir.getAbsolutePath());
        result.put("binPath", new File(javaDir, "bin").getAbsolutePath());
        result.put("javaExecutable", javaExecutable);

        return result;
    }

    /**
     * 查找java可执行文件
     */
    private String findJavaExecutable(File javaDir) {
        String os = System.getProperty("os.name").toLowerCase();
        String javaExeName = os.contains("win") ? "java.exe" : "java";

        // 尝试在bin目录下查找
        File binDir = new File(javaDir, "bin");
        if (binDir.exists() && binDir.isDirectory()) {
            File javaExe = new File(binDir, javaExeName);
            if (javaExe.exists() && javaExe.canExecute()) {
                return javaExe.getAbsolutePath();
            }
        }

        // 尝试直接在根目录查找
        File javaExe = new File(javaDir, javaExeName);
        if (javaExe.exists() && javaExe.canExecute()) {
            return javaExe.getAbsolutePath();
        }

        return null;
    }

    /**
     * 检测Java类型（JDK或JRE）
     * 通过检查javac编译器是否存在来判断
     */
    private String detectJavaType(File javaDir) {
        String os = System.getProperty("os.name").toLowerCase();
        String javacExeName = os.contains("win") ? "javac.exe" : "javac";

        // 检查bin目录下是否有javac
        File binDir = new File(javaDir, "bin");
        if (binDir.exists() && binDir.isDirectory()) {
            File javacExe = new File(binDir, javacExeName);
            if (javacExe.exists()) {
                return "JDK";
            }
        }

        // 检查根目录下是否有javac
        File javacExe = new File(javaDir, javacExeName);
        if (javacExe.exists()) {
            return "JDK";
        }

        return "JRE";
    }

    /**
     * 获取Java版本信息
     */
    private Map<String, String> getJavaVersion(String javaExecutable) {
        try {
            ProcessBuilder pb = new ProcessBuilder(javaExecutable, "-version");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            process.waitFor();
            String versionOutput = output.toString();

            return parseJavaVersion(versionOutput);
        } catch (Exception e) {
            log.error("获取Java版本失败", e);
            return null;
        }
    }

    /**
     * 解析Java版本信息
     */
    private Map<String, String> parseJavaVersion(String versionOutput) {
        Map<String, String> info = new HashMap<>();
        String lowerOutput = versionOutput.toLowerCase();

        // 解析版本号 (例如: java version "17.0.2" 或 openjdk version "11.0.12")
        Pattern versionPattern = Pattern.compile("version \"([^\"]+)\"");
        Matcher versionMatcher = versionPattern.matcher(versionOutput);
        if (versionMatcher.find()) {
            String fullVersion = versionMatcher.group(1);
            info.put("fullVersion", fullVersion);

            // 提取主版本号
            String version = extractMajorVersion(fullVersion);
            info.put("version", version);
        }

        // 解析供应商 - 优先级从高到低，更具体的在前面
        String vendor = "Unknown";

        // 1. 检查 Zulu (Azul Systems)
        if (lowerOutput.contains("zulu")) {
            vendor = "Zulu";
        }
        // 2. 检查 Adoptium (Eclipse Temurin)
        else if (lowerOutput.contains("temurin") || lowerOutput.contains("adoptium")) {
            vendor = "Adoptium";
        }
        // 3. 检查 Amazon Corretto
        else if (lowerOutput.contains("corretto")) {
            vendor = "Corretto";
        }
        // 4. 检查 Microsoft Build
        else if (lowerOutput.contains("microsoft")) {
            vendor = "Microsoft";
        }
        // 5. 检查 GraalVM
        else if (lowerOutput.contains("graalvm")) {
            vendor = "GraalVM";
        }
        // 6. 检查 Liberica
        else if (lowerOutput.contains("liberica")) {
            vendor = "Liberica";
        }
        // 7. 检查 SAP Machine
        else if (lowerOutput.contains("sapmachine")) {
            vendor = "SapMachine";
        }
        // 8. 检查 Oracle JDK (必须在 OpenJDK 之前检查)
        else if (lowerOutput.contains("oracle corporation") ||
                (lowerOutput.contains("oracle") && !lowerOutput.contains("openjdk"))) {
            vendor = "Oracle";
        }
        // 9. 检查 OpenJDK (最后检查，因为很多发行版都包含这个关键字)
        else if (lowerOutput.contains("openjdk")) {
            vendor = "OpenJDK";
        }
        // 10. 检查 IBM Semeru
        else if (lowerOutput.contains("semeru") || lowerOutput.contains("ibm")) {
            vendor = "IBM Semeru";
        }

        info.put("vendor", vendor);

        // 解析架构
        if (versionOutput.contains("64-Bit") || versionOutput.contains("x86_64") || versionOutput.contains("amd64")) {
            info.put("arch", "x64");
        } else if (versionOutput.contains("aarch64") || versionOutput.contains("arm64")) {
            info.put("arch", "arm64");
        } else if (versionOutput.contains("x86") || versionOutput.contains("i386") || versionOutput.contains("i686")) {
            info.put("arch", "x86");
        } else {
            info.put("arch", "x64"); // 默认x64
        }

        // 判断类型 (JDK/JRE)
        info.put("type", "JDK"); // 默认JDK，可以通过检查是否存在javac来判断

        return info;
    }

    /**
     * 提取主版本号
     */
    private String extractMajorVersion(String fullVersion) {
        // 处理新版本格式 (9+): 17.0.2, 11.0.12
        // 处理旧版本格式 (8-): 1.8.0_292
        if (fullVersion.startsWith("1.")) {
            // 旧格式: 1.8.0_292 -> 8
            String[] parts = fullVersion.split("\\.");
            if (parts.length >= 2) {
                return parts[1].split("_")[0];
            }
        } else {
            // 新格式: 17.0.2 -> 17
            String[] parts = fullVersion.split("\\.");
            if (parts.length >= 1) {
                return parts[0];
            }
        }
        return fullVersion;
    }

    /**
     * 扫描系统中的Java环境
     */
    private List<Map<String, Object>> scanSystemJavaEnvironments() {
        List<Map<String, Object>> environments = new ArrayList<>();
        Set<String> scannedPaths = new HashSet<>();

        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            // Windows系统扫描路径
            scanWindowsJavaEnvironments(environments, scannedPaths);
        } else {
            // Linux/Unix系统扫描路径
            scanUnixJavaEnvironments(environments, scannedPaths);
        }

        return environments;
    }

    /**
     * 扫描Windows系统的Java环境
     */
    private void scanWindowsJavaEnvironments(List<Map<String, Object>> environments, Set<String> scannedPaths) {
        // 常见安装路径
        String[] commonPaths = {
                // 标准Java安装路径
                "C:\\Program Files\\Java",
                "C:\\Program Files (x86)\\Java",

                // Adoptium (Eclipse Temurin)
                "C:\\Program Files\\Eclipse Adoptium",
                "C:\\Program Files\\Eclipse Foundation",

                // Azul Zulu
                "C:\\Program Files\\Zulu",
                "C:\\Program Files\\Azul",

                // Amazon Corretto
                "C:\\Program Files\\Amazon Corretto",

                // Microsoft OpenJDK
                "C:\\Program Files\\Microsoft",

                // Oracle JDK
                "C:\\Program Files\\Oracle",

                // BellSoft Liberica
                "C:\\Program Files\\BellSoft",
                "C:\\Program Files\\Liberica",

                // SAP Machine
                "C:\\Program Files\\SapMachine",

                // 环境变量
                System.getenv("JAVA_HOME"),
                System.getenv("JDK_HOME"),
                System.getenv("JRE_HOME")
        };

        for (String basePath : commonPaths) {
            if (basePath == null || basePath.trim().isEmpty()) continue;
            scanDirectory(new File(basePath), environments, scannedPaths, 2);
        }
    }

    /**
     * 扫描Unix/Linux系统的Java环境
     */
    private void scanUnixJavaEnvironments(List<Map<String, Object>> environments, Set<String> scannedPaths) {
        // 常见安装路径
        String[] commonPaths = {
                // Linux标准路径
                "/usr/lib/jvm",
                "/usr/java",
                "/usr/local/java",
                "/opt/java",
                "/opt/jdk",
                "/opt/jre",

                // Adoptium
                "/usr/lib/jvm/temurin",
                "/opt/adoptium",

                // Zulu
                "/usr/lib/jvm/zulu",
                "/opt/zulu",

                // Corretto
                "/usr/lib/jvm/corretto",
                "/opt/corretto",

                // Liberica
                "/usr/lib/jvm/liberica",
                "/opt/liberica",

                // SDKMAN
                System.getProperty("user.home") + "/.sdkman/candidates/java",

                // macOS路径
                "/Library/Java/JavaVirtualMachines",
                "/System/Library/Java/JavaVirtualMachines",

                // 环境变量
                System.getenv("JAVA_HOME"),
                System.getenv("JDK_HOME"),
                System.getenv("JRE_HOME")
        };

        for (String basePath : commonPaths) {
            if (basePath == null || basePath.trim().isEmpty()) continue;
            scanDirectory(new File(basePath), environments, scannedPaths, 2);
        }
    }

    /**
     * 递归扫描目录
     */
    private void scanDirectory(File dir, List<Map<String, Object>> environments, Set<String> scannedPaths, int depth) {
        if (dir == null || !dir.exists() || !dir.isDirectory() || depth <= 0) {
            return;
        }

        String canonicalPath;
        try {
            canonicalPath = dir.getCanonicalPath();
        } catch (Exception e) {
            return;
        }

        if (scannedPaths.contains(canonicalPath)) {
            return;
        }
        scannedPaths.add(canonicalPath);

        // 检查当前目录是否是Java环境
        String javaExecutable = findJavaExecutable(dir);
        if (javaExecutable != null) {
            try {
                Map<String, Object> envInfo = verifyAndGetJavaInfo(dir.getAbsolutePath());
                if (envInfo != null && Boolean.TRUE.equals(envInfo.get("valid"))) {
                    environments.add(envInfo);
                    return; // 找到后不再深入扫描
                }
            } catch (Exception e) {
                log.debug("扫描目录失败: {}", dir.getAbsolutePath(), e);
            }
        }

        // 递归扫描子目录
        File[] subDirs = dir.listFiles(File::isDirectory);
        if (subDirs != null) {
            for (File subDir : subDirs) {
                scanDirectory(subDir, environments, scannedPaths, depth - 1);
            }
        }
    }

    /**
     * 一键安装Java环境（流式响应）
     */
    @PostMapping("/install")
    public SseEmitter installJava(
            @RequestHeader(Node.Header.X_ENDLESS_TOKEN) String token,
            @RequestBody Map<String, Object> request) {

        // 验证令牌
        AccessTokens accessToken = validateToken(token);
        if (accessToken == null) {
            SseEmitter emitter =
                    new SseEmitter();
            try {
                emitter.send(SseEmitter.event()
                        .data(Map.of("error", "无效的访问令牌", "success", false)));
                emitter.complete();
            } catch (Exception e) {
                emitter.completeWithError(e);
            }
            return emitter;
        }

        String version = (String) request.get("version");
        String installPath = (String) request.get("installPath");
        String vendor = (String) request.getOrDefault("vendor", "Adoptium");

        if (version == null || version.trim().isEmpty() || installPath == null || installPath.trim().isEmpty()) {
            SseEmitter emitter =
                    new SseEmitter();
            try {
                emitter.send(SseEmitter.event()
                        .data(Map.of("error", "参数不完整", "success", false)));
                emitter.complete();
            } catch (Exception e) {
                emitter.completeWithError(e);
            }
            return emitter;
        }

        // 创建SSE发射器，超时时间10分钟
        SseEmitter emitter =
                new SseEmitter(600000L);

        // 异步执行安装
        new Thread(() -> {
            try {
                log.info("开始安装Java {} ({}), 安装路径: {}", version, vendor, installPath);
                installJavaEnvironmentWithProgress(version, installPath, vendor, emitter);
            } catch (Exception e) {
                log.error("安装Java环境失败", e);
                try {
                    emitter.send(SseEmitter.event()
                            .data(Map.of(
                                    "type", "error",
                                    "message", "安装失败: " + e.getMessage(),
                                    "success", false
                            )));
                    emitter.complete();
                } catch (Exception ex) {
                    emitter.completeWithError(ex);
                }
            }
        }).start();

        return emitter;
    }

    /**
     * 安装Java环境（带进度推送）
     */
    private void installJavaEnvironmentWithProgress(String version, String installPath, String vendor,
                                                    SseEmitter emitter) throws Exception {

        try {
            // 1. 创建安装目录
            sendProgress(emitter, "info", "正在创建安装目录...", 10);
            File installDir = new File(installPath);
            if (!installDir.exists()) {
                if (!installDir.mkdirs()) {
                    throw new Exception("无法创建安装目录: " + installPath);
                }
            }

            String os = System.getProperty("os.name").toLowerCase();
            String arch = System.getProperty("os.arch").toLowerCase();

            String normalizedArch;
            if (arch.contains("amd64") || arch.contains("x86_64")) {
                normalizedArch = "x64";
            } else if (arch.contains("aarch64") || arch.contains("arm64")) {
                normalizedArch = "aarch64";
            } else {
                normalizedArch = "x86";
            }

            // 2. 获取下载URL
            sendProgress(emitter, "info", "正在获取下载链接...", 20);
            String downloadUrl = getJavaDownloadUrl(version, vendor, os, normalizedArch);
            if (downloadUrl == null) {
                throw new Exception("不支持的Java版本或平台");
            }

            log.info("下载URL: {}", downloadUrl);

            // 3. 下载文件
            sendProgress(emitter, "info", "开始下载Java安装包...", 30);
            File downloadFile = downloadJavaPackageWithProgress(downloadUrl, installDir, version, emitter);

            // 4. 解压文件
            sendProgress(emitter, "info", "开始解压安装包...", 70);
            File extractedDir = extractJavaPackage(downloadFile, installDir);
            log.info("解压完成: {}", extractedDir.getAbsolutePath());

            // 5. 验证安装
            sendProgress(emitter, "info", "正在验证安装...", 90);
            Map<String, Object> verifyResult = verifyAndGetJavaInfo(extractedDir.getAbsolutePath());
            if (verifyResult != null && Boolean.TRUE.equals(verifyResult.get("valid"))) {
                // 删除下载的压缩包
                if (downloadFile.exists()) {
                    downloadFile.delete();
                }

                log.info("Java {} 安装成功", version);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("javaHome", extractedDir.getAbsolutePath());
                result.put("version", verifyResult.get("version"));
                result.put("vendor", verifyResult.get("vendor"));
                result.put("type", verifyResult.get("type"));
                result.put("arch", verifyResult.get("arch"));

                sendProgress(emitter, "success", "安装完成！", 100, result);
                emitter.complete();
            } else {
                throw new Exception("Java安装验证失败");
            }
        } catch (Exception e) {
            sendProgress(emitter, "error", "安装失败: " + e.getMessage(), 0);
            emitter.complete();
            throw e;
        }
    }

    /**
     * 发送进度信息
     */
    private void sendProgress(SseEmitter emitter,
                              String type, String message, int progress) {
        sendProgress(emitter, type, message, progress, null);
    }

    /**
     * 发送进度信息（带数据）
     */
    private void sendProgress(SseEmitter emitter,
                              String type, String message, int progress, Map<String, Object> data) {
        try {
            Map<String, Object> event = new HashMap<>();
            event.put("type", type);
            event.put("message", message);
            event.put("progress", progress);
            if (data != null) {
                event.putAll(data);
            }
            emitter.send(SseEmitter.event()
                    .data(event));
            log.info("[{}%] {}", progress, message);
        } catch (Exception e) {
            log.error("发送进度失败", e);
        }
    }

    /**
     * 安装Java环境（原方法保留，用于非流式调用）
     */
    private Map<String, Object> installJavaEnvironment(String version, String installPath, String vendor) throws Exception {
        Map<String, Object> result = new HashMap<>();

        // 创建安装目录
        File installDir = new File(installPath);
        if (!installDir.exists()) {
            if (!installDir.mkdirs()) {
                throw new Exception("无法创建安装目录: " + installPath);
            }
        }

        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();

        // 标准化架构名称
        String normalizedArch;
        if (arch.contains("amd64") || arch.contains("x86_64")) {
            normalizedArch = "x64";
        } else if (arch.contains("aarch64") || arch.contains("arm64")) {
            normalizedArch = "aarch64";
        } else {
            normalizedArch = "x86";
        }

        // 根据供应商获取下载URL
        String downloadUrl = getJavaDownloadUrl(version, vendor, os, normalizedArch);
        if (downloadUrl == null) {
            throw new Exception("不支持的Java版本或平台");
        }

        log.info("下载URL: {}", downloadUrl);
        result.put("downloadUrl", downloadUrl);

        // 下载文件 - 先创建临时文件，从响应头获取真实文件名
        log.info("开始下载Java安装包...");
        File downloadFile = downloadJavaPackage(downloadUrl, installDir, version);

        result.put("downloadFile", downloadFile.getAbsolutePath());
        log.info("下载完成");

        // 解压文件
        log.info("开始解压...");
        File extractedDir = extractJavaPackage(downloadFile, installDir);
        result.put("extractedDir", extractedDir.getAbsolutePath());
        log.info("解压完成: {}", extractedDir.getAbsolutePath());

        // 验证安装
        Map<String, Object> verifyResult = verifyAndGetJavaInfo(extractedDir.getAbsolutePath());
        if (verifyResult != null && Boolean.TRUE.equals(verifyResult.get("valid"))) {
            result.put("success", true);
            result.put("javaHome", extractedDir.getAbsolutePath());
            result.put("version", verifyResult.get("version"));
            result.put("vendor", verifyResult.get("vendor"));
            result.put("type", verifyResult.get("type"));
            result.put("arch", verifyResult.get("arch"));

            // 删除下载的压缩包
            if (downloadFile.exists()) {
                downloadFile.delete();
            }

            log.info("Java {} 安装成功", version);
        } else {
            throw new Exception("Java安装验证失败");
        }

        return result;
    }

    /**
     * 获取Java下载URL
     */
    private String getJavaDownloadUrl(String version, String vendor, String os, String arch) {
        return JavaDownloadUrlProvider.getDownloadUrl(version, vendor, os, arch);
    }

    /**
     * 下载Java安装包（带进度推送）
     */
    private File downloadJavaPackageWithProgress(String url, File installDir, String version,
                                                 SseEmitter emitter) throws Exception {
        java.net.URL downloadUrl = new java.net.URL(url);
        java.net.HttpURLConnection connection = (java.net.HttpURLConnection) downloadUrl.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(30000);
        connection.setReadTimeout(300000);
        connection.setInstanceFollowRedirects(true);

        try {
            connection.connect();

            String fileName = null;
            String contentDisposition = connection.getHeaderField("Content-Disposition");
            if (contentDisposition != null && contentDisposition.contains("filename=")) {
                int index = contentDisposition.indexOf("filename=");
                if (index > 0) {
                    fileName = contentDisposition.substring(index + 9);
                    fileName = fileName.replaceAll("\"", "").trim();
                }
            }

            if (fileName == null || fileName.isEmpty()) {
                String os = System.getProperty("os.name").toLowerCase();
                String extension = os.contains("win") ? "zip" : "tar.gz";
                fileName = "jdk-" + version + "." + extension;
            }

            fileName = fileName.replaceAll("[^a-zA-Z0-9._-]", "_");

            File targetFile = new File(installDir, fileName);
            log.info("下载Java安装包到: {}", targetFile.getAbsolutePath());

            try (java.io.InputStream in = connection.getInputStream();
                 java.io.FileOutputStream out = new java.io.FileOutputStream(targetFile)) {

                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytesRead = 0;
                long fileSize = connection.getContentLengthLong();
                long lastProgressTime = System.currentTimeMillis();
                int lastProgress = 30;

                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;

                    // 每2秒更新一次进度
                    long currentTime = System.currentTimeMillis();
                    if (currentTime - lastProgressTime > 2000) {
                        if (fileSize > 0) {
                            // 下载进度占30%-70%
                            int downloadProgress = (int) ((totalBytesRead * 40) / fileSize);
                            int currentProgress = 30 + downloadProgress;

                            String progressMsg = String.format("下载中... %d%% (%d MB / %d MB)",
                                    (int) ((totalBytesRead * 100) / fileSize),
                                    totalBytesRead / (1024 * 1024),
                                    fileSize / (1024 * 1024));

                            sendProgress(emitter, "info", progressMsg, currentProgress);
                            lastProgress = currentProgress;
                        } else {
                            String progressMsg = String.format("已下载: %d MB", totalBytesRead / (1024 * 1024));
                            sendProgress(emitter, "info", progressMsg, lastProgress);
                        }
                        lastProgressTime = currentTime;
                    }
                }

                log.info("下载完成，总大小: {} MB", totalBytesRead / (1024 * 1024));
            }

            return targetFile;
        } finally {
            connection.disconnect();
        }
    }

    /**
     * 下载Java安装包（原方法保留）
     */
    private File downloadJavaPackage(String url, File installDir, String version) throws Exception {
        java.net.URL downloadUrl = new java.net.URL(url);
        java.net.HttpURLConnection connection = (java.net.HttpURLConnection) downloadUrl.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(30000);
        connection.setReadTimeout(300000); // 5分钟超时
        connection.setInstanceFollowRedirects(true);

        try {
            connection.connect();

            // 从响应头获取文件名
            String fileName = null;
            String contentDisposition = connection.getHeaderField("Content-Disposition");
            if (contentDisposition != null && contentDisposition.contains("filename=")) {
                // 提取 filename="xxx" 或 filename=xxx
                int index = contentDisposition.indexOf("filename=");
                if (index > 0) {
                    fileName = contentDisposition.substring(index + 9);
                    fileName = fileName.replaceAll("\"", "").trim();
                }
            }

            // 如果没有从响应头获取到，使用默认文件名
            if (fileName == null || fileName.isEmpty()) {
                String os = System.getProperty("os.name").toLowerCase();
                String extension = os.contains("win") ? "zip" : "tar.gz";
                fileName = "jdk-" + version + "." + extension;
            }

            // 确保文件名安全（移除非法字符）
            fileName = fileName.replaceAll("[^a-zA-Z0-9._-]", "_");

            File targetFile = new File(installDir, fileName);
            log.info("下载Java安装包到: {}", targetFile.getAbsolutePath());

            try (java.io.InputStream in = connection.getInputStream();
                 java.io.FileOutputStream out = new java.io.FileOutputStream(targetFile)) {

                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytesRead = 0;
                long fileSize = connection.getContentLengthLong();
                long lastLogTime = System.currentTimeMillis();

                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;

                    // 每5秒打印一次进度
                    long currentTime = System.currentTimeMillis();
                    if (currentTime - lastLogTime > 5000) {
                        if (fileSize > 0) {
                            int progress = (int) ((totalBytesRead * 100) / fileSize);
                            log.info("下载进度: {}% ({} MB / {} MB)",
                                    progress,
                                    totalBytesRead / (1024 * 1024),
                                    fileSize / (1024 * 1024));
                        } else {
                            log.info("已下载: {} MB", totalBytesRead / (1024 * 1024));
                        }
                        lastLogTime = currentTime;
                    }
                }
                
                log.info("下载完成，总大小: {} MB", totalBytesRead / (1024 * 1024));
            }

            return targetFile;
        } finally {
            connection.disconnect();
        }
    }

    /**
     * 解压Java安装包
     */
    private File extractJavaPackage(File packageFile, File targetDir) throws Exception {
        String fileName = packageFile.getName().toLowerCase();

        if (fileName.endsWith(".zip")) {
            return extractZip(packageFile, targetDir);
        } else if (fileName.endsWith(".tar.gz") || fileName.endsWith(".tgz")) {
            return extractTarGz(packageFile, targetDir);
        } else {
            throw new Exception("不支持的压缩格式: " + fileName);
        }
    }

    /**
     * 解压ZIP文件
     */
    private File extractZip(File zipFile, File targetDir) throws Exception {
        File extractedDir = null;

        try (java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(
                new java.io.FileInputStream(zipFile))) {

            java.util.zip.ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File file = new File(targetDir, entry.getName());

                // 记录第一个目录作为Java主目录
                if (extractedDir == null && entry.isDirectory()) {
                    extractedDir = file;
                }

                if (entry.isDirectory()) {
                    file.mkdirs();
                } else {
                    file.getParentFile().mkdirs();
                    try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
                        byte[] buffer = new byte[8192];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }

                    // 在Unix系统上设置可执行权限
                    if (!System.getProperty("os.name").toLowerCase().contains("win")) {
                        if (file.getName().equals("java") || file.getName().equals("javac")) {
                            file.setExecutable(true);
                        }
                    }
                }
                zis.closeEntry();
            }
        }

        return extractedDir;
    }

    /**
     * 解压TAR.GZ文件
     */
    private File extractTarGz(File tarGzFile, File targetDir) throws Exception {
        // 注意：这需要Apache Commons Compress库
        // 如果没有该库，可以使用系统命令解压
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            throw new Exception("Windows系统不支持tar.gz格式，请使用zip格式");
        }

        // 使用系统命令解压
        ProcessBuilder pb = new ProcessBuilder("tar", "-xzf", tarGzFile.getAbsolutePath(), "-C", targetDir.getAbsolutePath());
        Process process = pb.start();
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new Exception("解压失败，退出码: " + exitCode);
        }

        // 查找解压后的Java目录
        File[] files = targetDir.listFiles(File::isDirectory);
        if (files != null && files.length > 0) {
            // 返回第一个目录（通常是Java主目录）
            for (File file : files) {
                if (findJavaExecutable(file) != null) {
                    return file;
                }
            }
            return files[0];
        }

        return targetDir;
    }

    /**
     * 验证令牌
     */
    private AccessTokens validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            log.warn("令牌为空");
            return null;
        }

        try {
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            if (accessToken == null) {
                log.warn("无效的令牌: {}", token);
            }

            return accessToken;
        } catch (Exception e) {
            log.error("验证令牌时发生错误", e);
            return null;
        }
    }
}
