package cc.endmc.endlessnode.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * 备份管理：列出备份、恢复备份。
 */
@Slf4j
@Service
public class BackupService {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    @Value("${endless.backup.root:./backups}")
    private String backupRoot;

    @Value("${endless.backup.include:world,world_nether,world_the_end,server.properties}")
    private String include;

    @Value("${endless.backup.keep:5}")
    private int keep;

    /**
     * 列出指定服务器的所有备份，按时间倒序
     */
    public List<BackupInfo> listBackups(Integer serverId) {
        if (serverId == null) return List.of();
        Path serverBackupDir = Paths.get(backupRoot, String.valueOf(serverId)).toAbsolutePath().normalize();
        if (!Files.exists(serverBackupDir) || !Files.isDirectory(serverBackupDir)) return List.of();

        List<BackupInfo> backups = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(serverBackupDir, "*.zip")) {
            for (Path zipPath : stream) {
                try {
                    String fileName = zipPath.getFileName().toString();
                    String timestamp = fileName.replace(".zip", "");
                    long size = Files.size(zipPath);
                    long lastModified = Files.getLastModifiedTime(zipPath).toMillis();
                    backups.add(new BackupInfo(fileName, timestamp, size, lastModified, zipPath.toString()));
                } catch (Exception e) {
                    log.debug("读取备份信息失败: {}", zipPath, e);
                }
            }
        } catch (IOException e) {
            log.error("列出备份目录失败: {}", serverBackupDir, e);
        }

        // 按时间倒序
        backups.sort((a, b) -> Long.compare(b.lastModified, a.lastModified));
        return backups;
    }

    /**
     * 恢复指定备份到服务器目录。
     * 恢复前会先备份当前目录状态。
     *
     * @param serverId    服务器 ID
     * @param backupFileName 备份文件名（如 20250101-120000.zip）
     * @param serverFilePath 服务器文件路径
     * @return 恢复结果
     */
    public RestoreResult restoreBackup(Integer serverId, String backupFileName, String serverFilePath) {
        if (serverId == null || backupFileName == null || serverFilePath == null) {
            return new RestoreResult(false, "参数不完整");
        }

        // 安全校验：仅允许文件名，不允许路径穿越
        if (backupFileName.contains("/") || backupFileName.contains("\\") || backupFileName.contains("..")) {
            return new RestoreResult(false, "非法的备份文件名");
        }

        Path serverBackupDir = Paths.get(backupRoot, String.valueOf(serverId)).toAbsolutePath().normalize();
        Path zipPath = serverBackupDir.resolve(backupFileName).normalize();

        // 确保 zipPath 在 serverBackupDir 内
        if (!zipPath.startsWith(serverBackupDir)) {
            return new RestoreResult(false, "非法的备份路径");
        }

        if (!Files.exists(zipPath)) {
            return new RestoreResult(false, "备份文件不存在: " + backupFileName);
        }

        Path serverDir = Paths.get(serverFilePath).toAbsolutePath().normalize();
        if (!Files.exists(serverDir) || !Files.isDirectory(serverDir)) {
            return new RestoreResult(false, "服务器目录不存在: " + serverFilePath);
        }

        try {
            // 恢复前先备份当前目录状态
            Files.createDirectories(serverBackupDir);
            String preRestoreName = "pre-restore-" + TS.format(LocalDateTime.now()) + ".zip";
            Path preRestoreZip = serverBackupDir.resolve(preRestoreName);
            try {
                zipDirectory(serverDir, preRestoreZip);
                log.info("恢复前备份已创建: {}", preRestoreZip);
            } catch (Exception e) {
                log.error("恢复前备份创建失败，中止恢复操作", e);
                return new RestoreResult(false, "恢复前备份创建失败: " + e.getMessage());
            }

            // 解压备份到服务器目录（覆盖同名文件）
            int restoredFiles = 0;
            try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(Files.newInputStream(zipPath)))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    Path entryPath = serverDir.resolve(entry.getName()).normalize();

                    // 安全校验：确保解压目标在服务器目录内
                    if (!entryPath.startsWith(serverDir)) {
                        log.warn("跳过不安全的 zip 条目: {}", entry.getName());
                        continue;
                    }

                    if (entry.isDirectory()) {
                        Files.createDirectories(entryPath);
                    } else {
                        Files.createDirectories(entryPath.getParent());
                        Files.copy(zis, entryPath, StandardCopyOption.REPLACE_EXISTING);
                        restoredFiles++;
                    }
                    zis.closeEntry();
                }
            }

            log.info("备份恢复完成：服务器 {}，文件 {}，恢复 {} 个文件", serverId, backupFileName, restoredFiles);
            return new RestoreResult(true, "恢复成功，共恢复 " + restoredFiles + " 个文件");

        } catch (Exception e) {
            log.error("恢复备份失败：服务器 {}，文件 {}", serverId, backupFileName, e);
            return new RestoreResult(false, "恢复失败: " + e.getMessage());
        }
    }

    /**
     * 执行单个服务器的备份
     */
    public void backupServer(cc.endmc.endlessnode.domain.ServerInstances server) throws IOException {
        backupServer(server, this.keep);
    }

    public void backupServer(cc.endmc.endlessnode.domain.ServerInstances server, int retainCount) throws IOException {
        if (server == null || server.getId() == null) return;
        String filePath = server.getFilePath();
        if (filePath == null || filePath.trim().isEmpty()) return;

        Path serverDir = Paths.get(filePath).toAbsolutePath().normalize();
        if (!Files.exists(serverDir) || !Files.isDirectory(serverDir)) return;

        Path serverBackupDir = Paths.get(backupRoot, String.valueOf(server.getId())).toAbsolutePath().normalize();
        Files.createDirectories(serverBackupDir);

        String fileName = TS.format(LocalDateTime.now()) + ".zip";
        Path zipPath = serverBackupDir.resolve(fileName);

        List<String> includeEntries = parseIncludeList();
        if (includeEntries.isEmpty()) return;

        try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(zipPath)))) {
            for (String entry : includeEntries) {
                Path target = serverDir.resolve(entry).normalize();
                if (!target.startsWith(serverDir) || !Files.exists(target)) continue;
                addToZip(zos, serverDir, target);
            }
        }

        rotateBackups(serverBackupDir, retainCount);
        log.info("备份已创建: server={}, file={}", server.getId(), zipPath);
    }

    private List<String> parseIncludeList() {
        if (include == null || include.trim().isEmpty()) return List.of();
        List<String> list = new ArrayList<>();
        for (String part : include.split(",")) {
            String s = part == null ? "" : part.trim();
            if (!s.isEmpty()) list.add(s);
        }
        return list;
    }

    private void addToZip(ZipOutputStream zos, Path baseDir, Path target) throws IOException {
        if (Files.isDirectory(target)) {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Path rel = baseDir.relativize(file);
                    zos.putNextEntry(new ZipEntry(rel.toString().replace('\\', '/')));
                    Files.copy(file, zos);
                    zos.closeEntry();
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            Path rel = baseDir.relativize(target);
            zos.putNextEntry(new ZipEntry(rel.toString().replace('\\', '/')));
            Files.copy(target, zos);
            zos.closeEntry();
        }
    }

    private void rotateBackups(Path serverBackupDir, int retainCount) throws IOException {
        int maxKeep = Math.max(retainCount, 0);
        if (maxKeep <= 0) return;
        List<Path> zips = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(serverBackupDir, "*.zip")) {
            for (Path p : stream) zips.add(p);
        }
        if (zips.size() <= maxKeep) return;
        zips.sort(Comparator.comparingLong(p -> p.toFile().lastModified()));
        for (int i = 0; i < zips.size() - maxKeep; i++) {
            try { Files.deleteIfExists(zips.get(i)); } catch (Exception e) { log.debug("删除旧备份失败: {}", e.getMessage()); }
        }
    }

    /**
     * 将目录打包为 ZIP 文件
     */
    private void zipDirectory(Path sourceDir, Path zipPath) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(zipPath)))) {
            Files.walkFileTree(sourceDir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    // 跳过已有的备份 ZIP 文件
                    if (file.toString().endsWith(".zip")) return FileVisitResult.CONTINUE;
                    Path relativePath = sourceDir.relativize(file);
                    zos.putNextEntry(new ZipEntry(relativePath.toString().replace('\\', '/')));
                    Files.copy(file, zos);
                    zos.closeEntry();
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    Path relativePath = sourceDir.relativize(dir);
                    if (!relativePath.toString().isEmpty()) {
                        zos.putNextEntry(new ZipEntry(relativePath.toString().replace('\\', '/') + "/"));
                        zos.closeEntry();
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                    log.warn("跳过无法读取的文件: {}", file, exc);
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    /**
     * 备份信息
     */
    public record BackupInfo(String fileName, String timestamp, long sizeBytes, long lastModified, String path) {
        public String sizeFormatted() {
            if (sizeBytes < 1024) return sizeBytes + " B";
            if (sizeBytes < 1024 * 1024) return String.format("%.1f KB", sizeBytes / 1024.0);
            if (sizeBytes < 1024L * 1024 * 1024) return String.format("%.1f MB", sizeBytes / (1024.0 * 1024));
            return String.format("%.1f GB", sizeBytes / (1024.0 * 1024 * 1024));
        }
    }

    /**
     * 恢复结果
     */
    public record RestoreResult(boolean success, String message) {
    }
}
