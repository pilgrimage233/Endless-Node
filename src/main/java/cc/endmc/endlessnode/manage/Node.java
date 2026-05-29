package cc.endmc.endlessnode.manage;

import java.io.OutputStreamWriter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 存储节点运行时信息的类。
 * 仅保留实际使用的运行时状态映射。
 */
public class Node {

    private static final Map<Integer, Process> RUNNING_SERVERS = new ConcurrentHashMap<>();
    private static final Map<Integer, OutputStreamWriter> SERVER_WRITERS = new ConcurrentHashMap<>();
    private static final Map<Integer, Thread> CONSOLE_THREADS = new ConcurrentHashMap<>();
    private static final Map<Integer, Long> SERVER_START_TIMES = new ConcurrentHashMap<>();

    public static Map<Integer, Process> getRunningServers() {
        return RUNNING_SERVERS;
    }

    public static Map<Integer, OutputStreamWriter> getServerWriters() {
        return SERVER_WRITERS;
    }

    public static Map<Integer, Thread> getConsoleThreads() {
        return CONSOLE_THREADS;
    }

    public static Map<Integer, Long> getServerStartTimes() {
        return SERVER_START_TIMES;
    }

    public static class Header {
        public static final String X_ENDLESS_TOKEN = "X-Endless-Token";
    }
}
