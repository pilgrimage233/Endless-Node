package cc.endmc.endlessnode.controller;


import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.AccessTokensService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
