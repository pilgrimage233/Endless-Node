package cc.endmc.endlessnode.common;

import cc.endmc.endlessnode.domain.AccessTokens;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 节点服务器缓存
 * 用于存储节点服务器的实例
 * 使用ConcurrentHashMap实现线程安全的缓存
 * 作者：Memory
 */
public class TokenCache {

    private static final ConcurrentHashMap<String, AccessTokens> map = new ConcurrentHashMap<>();

    public static void put(String key, AccessTokens value) {
        map.put(key, value);
    }

    public static AccessTokens get(String key) {
        return map.get(key);
    }

    public static void remove(String key) {
        map.remove(key);
    }

    public static void clear() {
        map.clear();
    }

    public static boolean containsKey(String key) {
        return map.containsKey(key);
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

}
