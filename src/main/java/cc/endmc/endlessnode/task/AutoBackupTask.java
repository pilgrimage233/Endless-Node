package cc.endmc.endlessnode.task;

import cc.endmc.endlessnode.domain.ServerInstances;
import cc.endmc.endlessnode.service.ServerInstancesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 自动化备份：按计划将服务器关键文件/存档打包，并在本地保留最近 N 份。
 * <p>
 * 默认关闭，避免影响现有行为；可通过配置启用。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AutoBackupTask {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final ServerInstancesService serverInstancesService;

    @Value("${endless.backup.enabled:false}")
    private boolean enabled;

    @Value("${endless.backup.root:./backups}")
    private String backupRoot;

    @Value("${endless.backup.keep:5}")
    private int keep;

    @Value("${endless.backup.include:world,world_nether,world_the_end,server.properties}")
    private String include;

    @Scheduled(cron = "${endless.backup.cron:0 0 */6 * * *}")
    public void runScheduledBackup() {
        if (!enabled) {
            return;
        }

        List<ServerInstances> instances;
        try {
            instances = serverInstancesService.list();
        } catch (Exception e) {
            log.warn("Auto backup skipped: cannot query server instances: {}", e.getMessage());
            return;
        }

        for (ServerInstances server : instances) {
            try {
                backupServer(server);
            } catch (Exception e) {
                log.warn("Auto backup failed for server {}: {}", safeId(server), e.getMessage());
            }
        }
    }

    private void backupServer(ServerInstances server) throws IOException {
        if (server == null || server.getId() == null) {
            return;
        }
        String filePath = server.getFilePath();
        if (filePath == null || filePath.trim().isEmpty()) {
            return;
        }

        Path serverDir = Paths.get(filePath).toAbsolutePath().normalize();
        if (!Files.exists(serverDir) || !Files.isDirectory(serverDir)) {
            return;
        }

        Path serverBackupDir = Paths.get(backupRoot, String.valueOf(server.getId())).toAbsolutePath().normalize();
        Files.createDirectories(serverBackupDir);

        String fileName = TS.format(LocalDateTime.now()) + ".zip";
        Path zipPath = serverBackupDir.resolve(fileName);

        List<String> includeEntries = parseIncludeList();
        if (includeEntries.isEmpty()) {
            return;
        }

        try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(zipPath)))) {
            for (String entry : includeEntries) {
                Path target = serverDir.resolve(entry).normalize();
                if (!target.startsWith(serverDir)) {
                    continue;
                }
                if (!Files.exists(target)) {
                    continue;
                }
                addToZip(zos, serverDir, target);
            }
        }

        rotateBackups(serverBackupDir);
        log.info("Auto backup created for server {}: {}", server.getId(), zipPath);
    }

    private void addToZip(ZipOutputStream zos, Path baseDir, Path target) throws IOException {
        if (Files.isDirectory(target)) {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    putFile(zos, baseDir, file);
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            putFile(zos, baseDir, target);
        }
    }

    private void putFile(ZipOutputStream zos, Path baseDir, Path file) throws IOException {
        Path rel = baseDir.relativize(file);
        String zipEntryName = rel.toString().replace('\\', '/');
        ZipEntry zipEntry = new ZipEntry(zipEntryName);
        zos.putNextEntry(zipEntry);
        Files.copy(file, zos);
        zos.closeEntry();
    }

    private void rotateBackups(Path serverBackupDir) throws IOException {
        int maxKeep = Math.max(keep, 0);
        if (maxKeep <= 0) {
            return;
        }

        List<Path> zips = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(serverBackupDir, "*.zip")) {
            for (Path p : stream) {
                zips.add(p);
            }
        }

        if (zips.size() <= maxKeep) {
            return;
        }

        zips.sort(Comparator.comparingLong(p -> p.toFile().lastModified()));
        int toDelete = zips.size() - maxKeep;
        for (int i = 0; i < toDelete; i++) {
            try {
                Files.deleteIfExists(zips.get(i));
            } catch (Exception e) {
                log.debug("Failed to delete old backup {}: {}", zips.get(i), e.getMessage());
            }
        }
    }

    private List<String> parseIncludeList() {
        if (include == null || include.trim().isEmpty()) {
            return List.of();
        }
        String[] parts = include.split(",");
        List<String> list = new ArrayList<>();
        for (String part : parts) {
            String s = part == null ? "" : part.trim();
            if (!s.isEmpty()) {
                list.add(s);
            }
        }
        return list;
    }

    private String safeId(ServerInstances server) {
        try {
            return server == null ? "null" : String.valueOf(server.getId());
        } catch (Exception e) {
            return "unknown";
        }
    }
}

