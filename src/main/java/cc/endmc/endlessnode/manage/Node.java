package cc.endmc.endlessnode.manage;

import java.io.OutputStreamWriter;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * ClassName: Node <br>
 * Description: 存储节点运行时信息的类 <br>
 * date: 2025/10/28 22:11 <br>
 *
 * @author Memory <br>
 * @since JDK 17+
 */

public class Node {

    // 存储正在运行的服务器进程
    private static final Map<Integer, Process> RUNNING_SERVERS = new ConcurrentHashMap<>();

    // 存储服务器控制台输出流
    private static final Map<Integer, OutputStreamWriter> SERVER_WRITERS = new ConcurrentHashMap<>();

    // 存储服务器控制台输出线程
    private static final Map<Integer, Thread> CONSOLE_THREADS = new ConcurrentHashMap<>();

    // 存储活跃的WebSocket会话
    private static final Map<String, Set<String>> ACTIVE_SESSIONS = new ConcurrentHashMap<>();

    // 线程池，用于管理控制台输出线程
    private static final ExecutorService EXECUTOR_SERVICE = Executors.newCachedThreadPool();

    public static Map<Integer, Process> getRunningServers() {
        return RUNNING_SERVERS;
    }

    public static Map<Integer, OutputStreamWriter> getServerWriters() {
        return SERVER_WRITERS;
    }

    public static Map<Integer, Thread> getConsoleThreads() {
        return CONSOLE_THREADS;
    }

    public static Map<String, Set<String>> getActiveSessions() {
        return ACTIVE_SESSIONS;
    }

    public static ExecutorService getExecutorService() {
        return EXECUTOR_SERVICE;
    }

    public static class Header {
        public static final String X_ENDLESS_TOKEN = "X-Endless-Token";
    }
}
