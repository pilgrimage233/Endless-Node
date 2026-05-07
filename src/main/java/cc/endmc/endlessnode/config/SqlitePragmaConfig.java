package cc.endmc.endlessnode.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.boot.context.event.ApplicationReadyEvent;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;

/**
 * SQLite 并发优化：启动时设置 WAL 等 PRAGMA，降低 database is locked 概率。
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SqlitePragmaConfig {

    private final DataSource dataSource;

    @Value("${endless.sqlite.enable-wal:true}")
    private boolean enableWal;

    @Value("${endless.sqlite.busy-timeout-ms:5000}")
    private int busyTimeoutMs;

    @EventListener(ApplicationReadyEvent.class)
    public void applyPragmas() {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {

            statement.execute("PRAGMA foreign_keys = ON;");
            statement.execute("PRAGMA busy_timeout = " + Math.max(busyTimeoutMs, 0) + ";");

            if (enableWal) {
                statement.execute("PRAGMA journal_mode = WAL;");
                statement.execute("PRAGMA synchronous = NORMAL;");
            }

            log.info("SQLite PRAGMA applied (wal={}, busy_timeout_ms={})", enableWal, busyTimeoutMs);
        } catch (Exception e) {
            log.warn("Failed to apply SQLite PRAGMA settings: {}", e.getMessage());
        }
    }
}

