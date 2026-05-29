package cc.endmc.endlessnode.common;

import cc.endmc.endlessnode.domain.AccessTokens;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 节点服务器缓存
 * 用于存储节点服务器的实例，支持基于过期时间的自动清理。
 */
public class TokenCache {

    private static final ConcurrentHashMap<String, AccessTokens> map = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Long> expireTimeMap = new ConcurrentHashMap<>();

    /** 默认 TTL：30 分钟（毫秒） */
    private static final long DEFAULT_TTL_MS = 30 * 60 * 1000L;

    /** 清理任务间隔：60 秒 */
    private static final long CLEANUP_INTERVAL_SEC = 60;

    private static final ScheduledExecutorService CLEANUP_EXECUTOR =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "TokenCache-Cleanup");
                t.setDaemon(true);
                return t;
            });

    static {
        CLEANUP_EXECUTOR.scheduleWithFixedDelay(
                TokenCache::evictExpired,
                CLEANUP_INTERVAL_SEC, CLEANUP_INTERVAL_SEC, TimeUnit.SECONDS);
    }

    public static void put(String key, AccessTokens value) {
        map.put(key, value);
        expireTimeMap.put(key, computeExpireTimestamp(value));
    }

    public static AccessTokens get(String key) {
        AccessTokens value = map.get(key);
        if (value == null) {
            return null;
        }
        // 惰性检查：如果已过期则移除
        Long expireAt = expireTimeMap.get(key);
        if (expireAt != null && System.currentTimeMillis() > expireAt) {
            remove(key);
            return null;
        }
        return value;
    }

    public static void remove(String key) {
        map.remove(key);
        expireTimeMap.remove(key);
    }

    public static void clear() {
        map.clear();
        expireTimeMap.clear();
    }

    public static boolean containsKey(String key) {
        return get(key) != null;
    }

    public static boolean containsValue(AccessTokens value) {
        return map.containsValue(value);
    }

    public static int size() {
        return map.size();
    }

    public static boolean isEmpty() {
        return map.isEmpty();
    }

    public static Map<String, AccessTokens> getMap() {
        return map;
    }

    /**
     * 根据 token 的 expiresAt 计算缓存过期时间戳。
     * 永不过期的 token 使用默认 TTL 兜底，避免无限驻留。
     */
    private static long computeExpireTimestamp(AccessTokens token) {
        if (token == null || token.getExpiresAt() == null) {
            return System.currentTimeMillis() + DEFAULT_TTL_MS;
        }
        long expiresAtMs = token.getExpiresAt().getTime();
        // 永不过期的 token 使用默认 TTL
        if (expiresAtMs == Long.MAX_VALUE) {
            return System.currentTimeMillis() + DEFAULT_TTL_MS;
        }
        return expiresAtMs;
    }

    /**
     * 清理所有已过期的缓存条目
     */
    private static void evictExpired() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Long> entry : expireTimeMap.entrySet()) {
            if (entry.getValue() != null && now > entry.getValue()) {
                String key = entry.getKey();
                map.remove(key);
                expireTimeMap.remove(key);
            }
        }
    }
}
