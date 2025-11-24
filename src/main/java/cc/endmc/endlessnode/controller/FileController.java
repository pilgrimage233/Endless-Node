package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.service.FileDownloadService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.swing.filechooser.FileSystemView;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {

    private final AccessTokensService accessTokensService;
    private final FileSystemView fileSystemView = FileSystemView.getFileSystemView();
    private final FileDownloadService fileDownloadService;

    /**
     * 获取文件列表
     *
     * @param path 目录路径，如果为空则返回根目录
     * @return 文件列表
     */
    @GetMapping("/list")
    public ResponseEntity<Map<String, Object>> listFiles(
            @RequestParam(required = false, defaultValue = "") String path) {

        try {
            // 检查是否为Windows系统
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("windows");

            // 如果是Windows系统且路径为空，返回所有可用驱动器
            if (isWindows && path.isEmpty()) {
                List<Map<String, Object>> drives = Arrays.stream(File.listRoots())
                        .map(drive -> {
                            Map<String, Object> driveInfo = new HashMap<>();
                            String volumeLabel = fileSystemView.getSystemDisplayName(drive);
                            driveInfo.put("name", volumeLabel);
                            driveInfo.put("path", drive.getPath());
                            // driveInfo.put("volumeLabel", volumeLabel);
                            driveInfo.put("isDirectory", true);
                            driveInfo.put("totalSpace", drive.getTotalSpace());
                            driveInfo.put("freeSpace", drive.getFreeSpace());
                            driveInfo.put("usableSpace", drive.getUsableSpace());
                            driveInfo.put("lastModified", 0L);
                            return driveInfo;
                        })
                        .collect(Collectors.toList());

                Map<String, Object> response = new HashMap<>();
                response.put("path", "");
                response.put("files", drives);
                response.put("success", true);
                return ResponseEntity.ok(response);
            }

            // 构建目标路径
            Path targetPath = path.isEmpty() ? Paths.get("/") : Paths.get(path);

            // 检查路径是否存在
            if (!Files.exists(targetPath)) {
                return ResponseEntity.notFound().build();
            }

            // 检查是否为目录
            if (!Files.isDirectory(targetPath)) {
                return ResponseEntity.badRequest().body(Map.of("error", "目录不存在或不是目录"));
            }

            // 获取目录内容
            List<Map<String, Object>> files = Files.list(targetPath)
                    .map(filePath -> {
                        Map<String, Object> fileInfo = new HashMap<>();
                        fileInfo.put("name", filePath.getFileName().toString());
                        fileInfo.put("path", filePath.toAbsolutePath().toString());
                        fileInfo.put("isDirectory", Files.isDirectory(filePath));

                        try {
                            fileInfo.put("totalSpace", Files.size(filePath));
                            fileInfo.put("lastModified", Files.getLastModifiedTime(filePath).toMillis());
                        } catch (IOException e) {
                            fileInfo.put("totalSpace", 0);
                            fileInfo.put("lastModified", 0);
                        }

                        return fileInfo;
                    })
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("path", path);
            response.put("files", files);
            response.put("success", true);

            return ResponseEntity.ok(response);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(Map.of("error", "获取文件列表失败:" + e.getMessage()));
        }
    }

    /**
     * 下载文件
     *
     * @param path 文件路径
     * @return 文件资源
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(
            @RequestParam String path) {

        try {
            // 构建文件路径
            Path filePath = Paths.get(path);

            // 检查文件是否存在
            if (!Files.exists(filePath)) {
                return ResponseEntity.notFound().build();
            }

            // 检查是否为文件
            if (Files.isDirectory(filePath)) {
                return ResponseEntity.badRequest().build();
            }

            // 创建资源
            Resource resource = new UrlResource(filePath.toUri());

            // 设置响应头
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                    .body(resource);
        } catch (MalformedURLException e) {
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * 上传文件
     *
     * @param path 目标路径
     * @param file 文件
     * @return 上传结果
     */
    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> uploadFile(
            @RequestParam("path") String path,
            @RequestParam(value = "file", required = false) MultipartFile file) {

        try {

            if (file == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "文件无效"));
            }
            String fileName = file.getOriginalFilename();
            // 构建目标路径
            Path targetPath = Paths.get(path);

            // 如果目标是目录，则添加文件名
            if (Files.isDirectory(targetPath) || !targetPath.toString().contains(".")) {
                targetPath = targetPath.resolve(fileName);
            }

            // 创建父目录（如果不存在）
            Path parent = targetPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            // 保存文件
            Files.copy(file.getInputStream(), targetPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("path", targetPath.toString());
            response.put("size", Files.size(targetPath));
            response.put("fileName", fileName);

            return ResponseEntity.ok(response);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "文件上传失败",
                    "details", e.getMessage(),
                    "path", path
            ));
        }
    }

    /**
     * 删除文件或目录
     *
     * @param path 路径
     * @return 删除结果
     */
    @DeleteMapping("/delete")
    public ResponseEntity<Map<String, Object>> deleteFile(
            @RequestParam String path) {

        try {
            // 构建目标路径
            Path targetPath = Paths.get(path);

            // 检查路径是否存在
            if (!Files.exists(targetPath)) {
                return ResponseEntity.notFound().build();
            }

            // 删除文件或目录
            if (Files.isDirectory(targetPath)) {
                deleteDirectory(targetPath);
            } else {
                Files.delete(targetPath);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("path", path);

            return ResponseEntity.ok(response);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(Map.of("error", "文件删除失败: " + e.getMessage()));
        }
    }

    /**
     * 递归删除目录
     *
     * @param directory 目录路径
     * @throws IOException IO异常
     */
    private void deleteDirectory(Path directory) throws IOException {
        Files.walk(directory)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
    }

    /**
     * 从HTTP URL下载文件
     *
     * @param url  文件URL
     * @param path 保存路径
     * @return 下载结果
     */
    @PostMapping("/download-from-url")
    public ResponseEntity<Map<String, Object>> downloadFromUrl(
            @RequestParam String url,
            @RequestParam String path) {
        try {
            // 验证URL格式
            if (url == null || url.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "URL不能为空"));
            }

            // 验证URL协议
            String lowerUrl = url.toLowerCase().trim();
            if (!lowerUrl.startsWith("http://") && !lowerUrl.startsWith("https://")) {
                return ResponseEntity.badRequest().body(Map.of("error", "仅支持HTTP和HTTPS协议"));
            }

            // 验证路径
            if (path == null || path.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "保存路径不能为空"));
            }

            // 构建目标路径
            Path targetPath = Paths.get(path);

            // 验证目标路径是否可写
            Path parentPath = targetPath.getParent();
            if (parentPath != null && Files.exists(parentPath) && !Files.isWritable(parentPath)) {
                return ResponseEntity.status(403).body(Map.of("error", "目标路径不可写"));
            }

            // 获取文件名（先尝试从URL获取，下载时会根据响应头更新）
            String fileName = fileDownloadService.extractFileNameFromUrl(url);

            // 如果目标是目录，则添加文件名
            if (Files.isDirectory(targetPath) || !targetPath.toString().contains(".")) {
                targetPath = targetPath.resolve(fileName);
            }

            // 异步开始下载
            fileDownloadService.downloadFileAsync(url, targetPath.toString());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "下载任务已启动");
            response.put("targetPath", targetPath.toString());
            response.put("fileName", fileName);
            response.put("url", url);

            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "参数错误: " + e.getMessage(),
                    "url", url,
                    "path", path
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "文件下载失败: " + e.getMessage(),
                    "url", url,
                    "path", path
            ));
        }
    }
}