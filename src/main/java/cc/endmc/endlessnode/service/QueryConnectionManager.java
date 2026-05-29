package cc.endmc.endlessnode.service;

import cc.endmc.endlessnode.domain.ServerInstances;
import cc.endmc.endlessnode.util.MinecraftServerQuery;
import cn.hutool.core.net.Ipv4Util;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.*;

/**
 * Minecraft Server Query 连接管理、端口分配与玩家信息查询。
 * 从 ServerController 中提取，职责单一。
 */
@Slf4j
@Service
public class QueryConnectionManager {

    private static final long QUERY_CONNECTION_TTL_MS = 30_000L;
    private static final int QUERY_PORT_RANGE_START = 25600;
    private static final int QUERY_PORT_RANGE_END = 27000;

    private final ConcurrentHashMap<Integer, CachedQueryConnection> connectionCache = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor;

    public QueryConnectionManager() {
        cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "QueryConnectionCleanup");
            t.setDaemon(true);
            return t;
        });
        cleanupExecutor.scheduleWithFixedDelay(this::cleanupExpired, 60, 60, TimeUnit.SECONDS);
    }

    @PreDestroy
    public void shutdown() {
        cleanupAll();
        cleanupExecutor.shutdownNow();
    }

    // ==================== 连接缓存管理 ====================

    public CachedQueryConnection getCached(Integer serverId) {
        if (serverId == null) return null;
        CachedQueryConnection cached = connectionCache.get(serverId);
        if (cached != null) {
            if (System.currentTimeMillis() - cached.timestamp < QUERY_CONNECTION_TTL_MS) {
                return cached;
            }
            remove(serverId);
        }
        return null;
    }

    public void cache(Integer serverId, MinecraftServerQuery query, String host, int port) {
        if (serverId == null || query == null) return;
        remove(serverId);
        connectionCache.put(serverId, new CachedQueryConnection(query, host, port, System.currentTimeMillis()));
        log.debug("缓存服务器 {} 的Query连接 (主机: {}, 端口: {})", serverId, host, port);
    }

    public void remove(Integer serverId) {
        if (serverId == null) return;
        CachedQueryConnection cached = connectionCache.remove(serverId);
        if (cached != null && cached.query != null) {
            try {
                cached.query.close();
            } catch (Exception e) {
                log.debug("关闭Query连接时发生错误: {}", e.getMessage());
            }
        }
    }

    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        for (Map.Entry<Integer, CachedQueryConnection> entry : connectionCache.entrySet()) {
            if (entry.getValue() != null && now - entry.getValue().timestamp >= QUERY_CONNECTION_TTL_MS) {
                CachedQueryConnection removed = connectionCache.remove(entry.getKey());
                if (removed != null && removed.query != null) {
                    try {
                        removed.query.close();
                    } catch (Exception e) {
                        log.debug("关闭过期Query连接时发生错误: {}", e.getMessage());
                    }
                }
            }
        }
    }

    public void cleanupAll() {
        for (CachedQueryConnection cached : connectionCache.values()) {
            if (cached != null && cached.query != null) {
                try {
                    cached.query.close();
                } catch (Exception e) {
                    log.debug("清理Query连接时发生错误: {}", e.getMessage());
                }
            }
        }
        connectionCache.clear();
    }

    // ==================== 端口管理 ====================

    public int getOrAssignQueryPort(ServerInstances server) {
        if (server == null) return QUERY_PORT_RANGE_START;
        File propsFile = new File(server.getFilePath(), "server.properties");
        if (propsFile.exists()) {
            try {
                Properties props = new Properties();
                try (FileInputStream fis = new FileInputStream(propsFile)) {
                    props.load(fis);
                }
                String val = props.getProperty("query.port");
                if (val != null && !val.trim().isEmpty()) {
                    int port = Integer.parseInt(val.trim());
                    if (port > 0 && port <= 65535) {
                        return port;
                    }
                }
            } catch (Exception e) {
                log.debug("读取server.properties失败: {}", e.getMessage());
            }
        }
        return findAvailablePort();
    }

    public int getServerPort(ServerInstances server) {
        File propsFile = new File(server.getFilePath(), "server.properties");
        if (propsFile.exists()) {
            try {
                Properties props = new Properties();
                try (FileInputStream fis = new FileInputStream(propsFile)) {
                    props.load(fis);
                }
                String val = props.getProperty("server-port");
                if (val != null && !val.trim().isEmpty()) {
                    int port = Integer.parseInt(val.trim());
                    if (port > 0 && port <= 65535) return port;
                }
            } catch (Exception e) {
                log.debug("读取server.properties失败: {}", e.getMessage());
            }
        }
        return 25565;
    }

    public int findAvailablePort() {
        Random random = new Random();
        int start = QUERY_PORT_RANGE_START + random.nextInt(QUERY_PORT_RANGE_END - QUERY_PORT_RANGE_START);
        for (int i = 0; i < (QUERY_PORT_RANGE_END - QUERY_PORT_RANGE_START); i++) {
            int port = start + i;
            if (port > QUERY_PORT_RANGE_END) {
                port = QUERY_PORT_RANGE_START + (port - QUERY_PORT_RANGE_END - 1);
            }
            if (isPortAvailable(port)) return port;
        }
        return QUERY_PORT_RANGE_START;
    }

    private boolean isPortAvailable(int port) {
        try (ServerSocket ss = new ServerSocket(port)) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== Query 配置管理 ====================

    public void ensureQueryEnabled(ServerInstances server) {
        if (server == null || server.getFilePath() == null) return;
        try {
            File propsFile = new File(server.getFilePath(), "server.properties");
            if (!propsFile.exists()) {
                createDefaultProperties(propsFile, server);
                return;
            }
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(propsFile)) {
                props.load(fis);
            }
            boolean needUpdate = false;
            if (!"true".equals(props.getProperty("enable-query"))) {
                props.setProperty("enable-query", "true");
                needUpdate = true;
            }
            String currentQueryPort = props.getProperty("query.port");
            if (currentQueryPort == null || currentQueryPort.trim().isEmpty()) {
                props.setProperty("query.port", String.valueOf(findAvailablePort()));
                needUpdate = true;
            } else {
                try {
                    int p = Integer.parseInt(currentQueryPort.trim());
                    if (p <= 0 || p > 65535) {
                        props.setProperty("query.port", String.valueOf(findAvailablePort()));
                        needUpdate = true;
                    }
                } catch (NumberFormatException e) {
                    props.setProperty("query.port", String.valueOf(findAvailablePort()));
                    needUpdate = true;
                }
            }
            if (needUpdate) {
                File backup = new File(propsFile.getParent(), "server.properties.backup");
                try {
                    Files.copy(propsFile.toPath(), backup.toPath(), StandardCopyOption.REPLACE_EXISTING);
                } catch (Exception e) {
                    log.warn("备份server.properties失败: {}", e.getMessage());
                }
                try (FileOutputStream fos = new FileOutputStream(propsFile)) {
                    props.store(fos, "Updated by Endless-Node to enable Query - " + new Date());
                }
            }
        } catch (Exception e) {
            log.error("配置服务器 {} 的Query功能时发生错误", server.getId(), e);
        }
    }

    private void createDefaultProperties(File propsFile, ServerInstances server) {
        try {
            Properties props = new Properties();
            props.setProperty("server-port", String.valueOf(getServerPort(server)));
            props.setProperty("enable-query", "true");
            props.setProperty("query.port", String.valueOf(findAvailablePort()));
            props.setProperty("gamemode", "survival");
            props.setProperty("difficulty", "easy");
            props.setProperty("max-players", "20");
            props.setProperty("online-mode", "true");
            props.setProperty("white-list", "false");
            props.setProperty("motd", "A Minecraft Server");
            try (FileOutputStream fos = new FileOutputStream(propsFile)) {
                props.store(fos, "Default server.properties created by Endless-Node - " + new Date());
            }
        } catch (Exception e) {
            log.error("创建默认server.properties失败", e);
        }
    }

    // ==================== 玩家信息查询 ====================

    /**
     * 通过 Query 协议查询服务器在线玩家，自动尝试缓存连接和新连接。
     *
     * @return 查询结果，失败时返回 null
     */
    public QueryResult queryPlayers(Integer serverId, ServerInstances server) {
        // 1. 尝试缓存连接
        CachedQueryConnection cached = getCached(serverId);
        if (cached != null && cached.isValid()) {
            try {
                MinecraftServerQuery.ServerStatus status = cached.query.getFullStatus();
                if (status != null) {
                    return new QueryResult(true, status, cached.host, cached.port, "query-cached");
                }
            } catch (Exception e) {
                log.debug("缓存的Query连接失效: {}", e.getMessage());
                remove(serverId);
            }
        }

        // 2. 尝试新连接
        int queryPort = getOrAssignQueryPort(server);
        try {
            String localIp = InetAddress.getLocalHost().getHostAddress();
            String[] hosts = {localIp, Ipv4Util.LOCAL_IP};
            for (String host : hosts) {
                MinecraftServerQuery query = new MinecraftServerQuery(host, queryPort);
                try {
                    if (query.connectWithRetry(2, 1000)) {
                        MinecraftServerQuery.ServerStatus status = query.getFullStatus();
                        if (status != null) {
                            cache(serverId, query, host, queryPort);
                            return new QueryResult(true, status, host, queryPort, "query");
                        }
                    }
                } catch (Exception e) {
                    log.debug("Query连接失败 ({}:{}): {}", host, queryPort, e.getMessage());
                }
                query.close();
            }
        } catch (Exception e) {
            log.debug("获取本机IP失败: {}", e.getMessage());
        }

        return null;
    }

    /**
     * 构建玩家信息响应 Map
     */
    public Map<String, Object> buildPlayerResponse(Integer serverId, ServerInstances server,
                                                    MinecraftServerQuery.ServerStatus status,
                                                    String host, int port, String method) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("serverId", serverId);
        response.put("method", method);
        response.put("queryHost", host);
        response.put("queryPort", port);
        response.put("serverInfo", Map.of(
                "motd", status.getMotd() != null ? status.getMotd() : "",
                "version", status.getVersion() != null ? status.getVersion() : "",
                "gameType", status.getGameType() != null ? status.getGameType() : "",
                "map", status.getMap() != null ? status.getMap() : "",
                "plugins", status.getPlugins() != null ? status.getPlugins() : ""
        ));
        List<Map<String, Object>> players = new ArrayList<>();
        for (String name : status.getPlayerList()) {
            players.add(Map.of("name", name, "joinTime", System.currentTimeMillis()));
        }
        response.put("players", players);
        response.put("playerCount", Map.of("online", status.getOnlinePlayers(), "max", status.getMaxPlayers()));
        return response;
    }

    /**
     * Query 查询结果
     */
    public record QueryResult(boolean success, MinecraftServerQuery.ServerStatus status,
                               String host, int port, String method) {
    }

    /**
     * 缓存的 Query 连接
     */
    public static class CachedQueryConnection {
        public final MinecraftServerQuery query;
        public final String host;
        public final int port;
        public final long timestamp;

        public CachedQueryConnection(MinecraftServerQuery query, String host, int port, long timestamp) {
            this.query = query;
            this.host = host;
            this.port = port;
            this.timestamp = timestamp;
        }

        public boolean isValid() {
            return query != null && System.currentTimeMillis() - timestamp < QUERY_CONNECTION_TTL_MS;
        }
    }
}
