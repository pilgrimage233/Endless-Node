package cc.endmc.endlessnode.util;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Minecraft Server Query 客户端
 * 实现 Minecraft 官方的 Server Query 协议
 * 用于获取服务器状态和在线玩家信息
 */
@Slf4j
public class MinecraftServerQuery {

    private static final int QUERY_MAGIC = 0xFEFD;
    private static final byte TYPE_HANDSHAKE = 9;
    private static final byte TYPE_STAT = 0;
    private static final int TIMEOUT_MS = 5000;

    private final String host;
    private final int port;
    private DatagramSocket socket;
    private int sessionId;
    private int challengeToken;

    public MinecraftServerQuery(String host, int port) {
        this.host = host;
        this.port = port;
        this.sessionId = new Random().nextInt();
    }

    /**
     * 静态方法：测试Query连接是否可用
     */
    public static boolean testQueryConnection(String host, int port) {
        MinecraftServerQuery query = new MinecraftServerQuery(host, port);
        try {
            return query.connect();
        } finally {
            query.close();
        }
    }

    /**
     * 静态方法：快速获取服务器状态（带超时）
     */
    public static ServerStatus quickGetStatus(String host, int port, int timeoutMs) {
        MinecraftServerQuery query = new MinecraftServerQuery(host, port);

        try {
            query.socket = new DatagramSocket();
            query.socket.setSoTimeout(timeoutMs);

            if (query.sendHandshake() && query.receiveHandshake()) {
                return query.getFullStatus();
            }
        } catch (Exception e) {
            log.debug("快速状态获取失败: {}", e.getMessage());
        } finally {
            query.close();
        }

        return null;
    }

    /**
     * 静态方法：详细的连接测试（用于诊断）
     */
    public static Map<String, Object> detailedConnectionTest(String host, int port) {
        Map<String, Object> result = new HashMap<>();
        result.put("host", host);
        result.put("port", port);
        result.put("timestamp", System.currentTimeMillis());

        MinecraftServerQuery query = new MinecraftServerQuery(host, port);

        try {
            // 第一步：测试连接
            result.put("socketCreated", true);

            // 第二步：测试握手
            boolean handshakeSuccess = query.connectWithRetry(1, 0);
            result.put("handshakeSuccess", handshakeSuccess);

            if (handshakeSuccess) {
                // 第三步：测试状态获取
                try {
                    ServerStatus status = query.getFullStatus();
                    if (status != null) {
                        result.put("statusSuccess", true);
                        result.put("onlinePlayers", status.getOnlinePlayers());
                        result.put("maxPlayers", status.getMaxPlayers());
                        result.put("motd", status.getMotd());
                        result.put("version", status.getVersion());
                        result.put("playerCount", status.getPlayerList().size());
                    } else {
                        result.put("statusSuccess", false);
                        result.put("statusError", "状态响应为空");
                    }
                } catch (Exception e) {
                    result.put("statusSuccess", false);
                    result.put("statusError", e.getMessage());
                }
            } else {
                result.put("handshakeError", "握手失败");
            }

        } catch (Exception e) {
            result.put("socketCreated", false);
            result.put("error", e.getMessage());
        } finally {
            query.close();
        }

        return result;
    }

    /**
     * 连接到服务器并进行握手
     */
    public boolean connect() {
        return connectWithRetry(3, 2000);
    }

    /**
     * 带重试的连接方法
     */
    public boolean connectWithRetry(int maxRetries, long retryDelayMs) {
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                log.debug("尝试连接到服务器: {}:{} (第 {}/{} 次)", host, port, attempt, maxRetries);

                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }

                socket = new DatagramSocket();
                socket.setSoTimeout(TIMEOUT_MS);

                // 发送握手请求
                log.debug("发送握手请求...");
                if (!sendHandshake()) {
                    log.warn("发送握手请求失败");
                    continue;
                }

                // 接收握手响应
                log.debug("等待握手响应...");
                boolean result = receiveHandshake();
                if (result) {
                    log.debug("握手成功完成 (第 {} 次尝试)", attempt);
                    return true;
                } else {
                    log.warn("握手失败 (第 {} 次尝试)", attempt);
                }

            } catch (java.net.SocketTimeoutException e) {
                log.warn("连接超时: {}:{} (第 {}/{} 次尝试) - 可能服务器未启用Query或端口不正确",
                        host, port, attempt, maxRetries);
            } catch (java.net.ConnectException e) {
                log.warn("连接被拒绝: {}:{} (第 {}/{} 次尝试) - 端口可能未开放",
                        host, port, attempt, maxRetries);
            } catch (Exception e) {
                log.warn("连接到服务器失败: {}:{} (第 {}/{} 次尝试): {}",
                        host, port, attempt, maxRetries, e.getMessage());
            }

            // 如果不是最后一次尝试，等待一段时间再重试
            if (attempt < maxRetries) {
                try {
                    Thread.sleep(retryDelayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    log.warn("重试等待被中断");
                    break;
                }
            }
        }

        log.error("所有连接尝试都失败了: {}:{}", host, port);
        return false;
    }

    /**
     * 获取服务器基本状态信息
     */
    public ServerStatus getBasicStatus() {
        if (socket == null) {
            log.warn("未连接到服务器");
            return null;
        }

        try {
            // 发送基本状态查询
            sendBasicStatRequest();

            // 接收响应
            return receiveBasicStatResponse();
        } catch (Exception e) {
            log.error("获取服务器基本状态失败", e);
            return null;
        }
    }

    /**
     * 获取服务器完整状态信息（包括玩家列表）
     */
    public ServerStatus getFullStatus() {
        if (socket == null) {
            log.warn("未连接到服务器");
            return null;
        }

        try {
            // 发送完整状态查询
            sendFullStatRequest();

            // 接收响应
            return receiveFullStatResponse();
        } catch (Exception e) {
            log.error("获取服务器完整状态失败", e);
            return null;
        }
    }

    /**
     * 关闭连接
     */
    public void close() {
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }

    /**
     * 发送握手请求
     */
    private boolean sendHandshake() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Minecraft Query协议使用大端序
        dos.writeShort(QUERY_MAGIC);
        dos.writeByte(TYPE_HANDSHAKE);
        dos.writeInt(sessionId);

        byte[] data = baos.toByteArray();

        if (log.isDebugEnabled()) {
            StringBuilder hexDump = new StringBuilder();
            for (int i = 0; i < data.length; i++) {
                hexDump.append(String.format("%02X ", data[i] & 0xFF));
            }
            log.debug("发送握手请求数据: {}", hexDump.toString());
            log.debug("发送的会话ID: {}", sessionId);
        }

        DatagramPacket packet = new DatagramPacket(data, data.length,
                InetAddress.getByName(host), port);

        socket.send(packet);
        return true;
    }

    /**
     * 接收握手响应
     */
    private boolean receiveHandshake() throws IOException {
        byte[] buffer = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        socket.receive(packet);

        // 调试：打印接收到的数据
        log.debug("接收到握手响应，数据长度: {}", packet.getLength());
        if (log.isDebugEnabled()) {
            StringBuilder hexDump = new StringBuilder();
            for (int i = 0; i < Math.min(packet.getLength(), 32); i++) {
                hexDump.append(String.format("%02X ", buffer[i] & 0xFF));
            }
            log.debug("握手响应数据 (前32字节): {}", hexDump.toString());
        }

        if (packet.getLength() < 5) {
            log.warn("握手响应数据长度不足: {}", packet.getLength());
            return false;
        }

        DataInputStream dis = new DataInputStream(
                new java.io.ByteArrayInputStream(packet.getData(), 0, packet.getLength()));

        try {
            byte type = dis.readByte();
            int receivedSessionId = dis.readInt();

            log.debug("握手响应 - 类型: {}, 会话ID: {}, 期望会话ID: {}", type, receivedSessionId, sessionId);

            if (type != TYPE_HANDSHAKE) {
                log.warn("握手响应类型无效: {} (期望: {})", type, TYPE_HANDSHAKE);
                return false;
            }

            // 检查会话ID是否匹配
            // 注意：某些服务器可能会修改会话ID，我们需要更宽松的验证
            if (receivedSessionId != sessionId) {
                log.debug("会话ID不匹配，更新为服务器返回的值。收到: {}, 原始: {}", receivedSessionId, sessionId);
                // 更新会话ID为服务器返回的值，这是正常的Query协议行为
                sessionId = receivedSessionId;
            }

            // 读取挑战令牌 - 以null结尾的字符串
            StringBuilder tokenStr = new StringBuilder();
            byte b;
            int bytesRead = 5; // 已读取type(1) + sessionId(4)

            while (bytesRead < packet.getLength() && (b = dis.readByte()) != 0) {
                if (b >= 32 && b <= 126) { // 可打印ASCII字符
                    tokenStr.append((char) b);
                }
                bytesRead++;
            }

            if (tokenStr.length() == 0) {
                log.error("未找到挑战令牌");
                return false;
            }

            try {
                String tokenString = tokenStr.toString().trim();
                challengeToken = Integer.parseInt(tokenString);
                log.debug("握手成功，挑战令牌: {}", challengeToken);
                return true;
            } catch (NumberFormatException e) {
                log.error("解析挑战令牌失败: '{}', 长度: {}", tokenStr.toString(), tokenStr.length());
                return false;
            }

        } catch (Exception e) {
            log.error("解析握手响应时发生错误", e);
            return false;
        }
    }

    /**
     * 发送基本状态查询请求
     */
    private void sendBasicStatRequest() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeShort(QUERY_MAGIC);
        dos.writeByte(TYPE_STAT);
        dos.writeInt(sessionId);
        dos.writeInt(challengeToken);

        byte[] data = baos.toByteArray();

        if (log.isDebugEnabled()) {
            log.debug("发送基本状态查询，会话ID: {}, 挑战令牌: {}", sessionId, challengeToken);
        }

        DatagramPacket packet = new DatagramPacket(data, data.length,
                InetAddress.getByName(host), port);

        socket.send(packet);
    }

    /**
     * 发送完整状态查询请求
     */
    private void sendFullStatRequest() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeShort(QUERY_MAGIC);
        dos.writeByte(TYPE_STAT);
        dos.writeInt(sessionId);
        dos.writeInt(challengeToken);
        dos.writeInt(0); // 完整查询标识

        byte[] data = baos.toByteArray();

        if (log.isDebugEnabled()) {
            log.debug("发送完整状态查询，会话ID: {}, 挑战令牌: {}", sessionId, challengeToken);
        }

        DatagramPacket packet = new DatagramPacket(data, data.length,
                InetAddress.getByName(host), port);

        socket.send(packet);
    }

    /**
     * 接收基本状态响应
     */
    private ServerStatus receiveBasicStatResponse() throws IOException {
        byte[] buffer = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        socket.receive(packet);

        log.debug("接收到基本状态响应，数据长度: {}", packet.getLength());

        DataInputStream dis = new DataInputStream(
                new java.io.ByteArrayInputStream(packet.getData(), 0, packet.getLength()));

        byte type = dis.readByte();
        int receivedSessionId = dis.readInt();

        log.debug("基本状态响应 - 类型: {}, 会话ID: {}, 期望会话ID: {}", type, receivedSessionId, sessionId);

        if (type != TYPE_STAT) {
            log.warn("基本状态响应类型无效: {} (期望: {})", type, TYPE_STAT);
            return null;
        }

        if (receivedSessionId != sessionId) {
            log.warn("基本状态响应会话ID无效: {} (期望: {})", receivedSessionId, sessionId);
            return null;
        }

        ServerStatus status = new ServerStatus();

        // 读取MOTD
        status.setMotd(readNullTerminatedString(dis));

        // 读取游戏类型
        status.setGameType(readNullTerminatedString(dis));

        // 读取地图名称
        status.setMap(readNullTerminatedString(dis));

        // 读取在线玩家数
        String onlinePlayersStr = readNullTerminatedString(dis);
        try {
            status.setOnlinePlayers(Integer.parseInt(onlinePlayersStr));
        } catch (NumberFormatException e) {
            status.setOnlinePlayers(0);
        }

        // 读取最大玩家数
        String maxPlayersStr = readNullTerminatedString(dis);
        try {
            status.setMaxPlayers(Integer.parseInt(maxPlayersStr));
        } catch (NumberFormatException e) {
            status.setMaxPlayers(0);
        }

        // 读取端口（小端序）
        byte[] portBytes = new byte[2];
        dis.readFully(portBytes);
        ByteBuffer bb = ByteBuffer.wrap(portBytes);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        status.setPort(bb.getShort() & 0xFFFF);

        // 读取主机名
        status.setHostname(readNullTerminatedString(dis));

        return status;
    }

    /**
     * 接收完整状态响应
     */
    private ServerStatus receiveFullStatResponse() throws IOException {
        byte[] buffer = new byte[4096];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        socket.receive(packet);

        log.debug("接收到完整状态响应，数据长度: {}", packet.getLength());

        DataInputStream dis = new DataInputStream(
                new java.io.ByteArrayInputStream(packet.getData(), 0, packet.getLength()));

        byte type = dis.readByte();
        int receivedSessionId = dis.readInt();

        log.debug("完整状态响应 - 类型: {}, 会话ID: {}, 期望会话ID: {}", type, receivedSessionId, sessionId);

        if (type != TYPE_STAT) {
            log.warn("完整状态响应类型无效: {} (期望: {})", type, TYPE_STAT);
            return null;
        }

        if (receivedSessionId != sessionId) {
            log.warn("完整状态响应会话ID无效: {} (期望: {})", receivedSessionId, sessionId);
            return null;
        }

        ServerStatus status = new ServerStatus();

        // 跳过填充字节
        dis.skipBytes(11);

        // 读取键值对
        Map<String, String> properties = new HashMap<>();
        String key;
        while (!(key = readNullTerminatedString(dis)).isEmpty()) {
            String value = readNullTerminatedString(dis);
            properties.put(key, value);
        }

        // 解析属性
        status.setMotd(properties.get("hostname"));
        status.setGameType(properties.get("gametype"));
        status.setMap(properties.get("map"));

        try {
            status.setOnlinePlayers(Integer.parseInt(properties.getOrDefault("numplayers", "0")));
        } catch (NumberFormatException e) {
            status.setOnlinePlayers(0);
        }

        try {
            status.setMaxPlayers(Integer.parseInt(properties.getOrDefault("maxplayers", "0")));
        } catch (NumberFormatException e) {
            status.setMaxPlayers(0);
        }

        try {
            status.setPort(Integer.parseInt(properties.getOrDefault("hostport", "25565")));
        } catch (NumberFormatException e) {
            status.setPort(25565);
        }

        status.setHostname(properties.get("hostip"));
        status.setVersion(properties.get("version"));
        status.setPlugins(properties.get("plugins"));

        // 跳过到玩家列表部分
        dis.skipBytes(10);

        // 读取玩家列表
        List<String> players = new ArrayList<>();
        String playerName;
        while (!(playerName = readNullTerminatedString(dis)).isEmpty()) {
            players.add(playerName);
        }

        status.setPlayerList(players);

        return status;
    }

    /**
     * 读取以null结尾的字符串
     */
    private String readNullTerminatedString(DataInputStream dis) throws IOException {
        StringBuilder sb = new StringBuilder();
        byte b;
        while ((b = dis.readByte()) != 0) {
            sb.append((char) b);
        }
        return sb.toString();
    }

    /**
     * 服务器状态信息类
     */
    public static class ServerStatus {
        private String motd;
        private String gameType;
        private String map;
        private int onlinePlayers;
        private int maxPlayers;
        private int port;
        private String hostname;
        private String version;
        private String plugins;
        private List<String> playerList = new ArrayList<>();

        // Getters and Setters
        public String getMotd() {
            return motd;
        }

        public void setMotd(String motd) {
            this.motd = motd;
        }

        public String getGameType() {
            return gameType;
        }

        public void setGameType(String gameType) {
            this.gameType = gameType;
        }

        public String getMap() {
            return map;
        }

        public void setMap(String map) {
            this.map = map;
        }

        public int getOnlinePlayers() {
            return onlinePlayers;
        }

        public void setOnlinePlayers(int onlinePlayers) {
            this.onlinePlayers = onlinePlayers;
        }

        public int getMaxPlayers() {
            return maxPlayers;
        }

        public void setMaxPlayers(int maxPlayers) {
            this.maxPlayers = maxPlayers;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public String getHostname() {
            return hostname;
        }

        public void setHostname(String hostname) {
            this.hostname = hostname;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public String getPlugins() {
            return plugins;
        }

        public void setPlugins(String plugins) {
            this.plugins = plugins;
        }

        public List<String> getPlayerList() {
            return playerList;
        }

        public void setPlayerList(List<String> playerList) {
            this.playerList = playerList;
        }

        /**
         * 转换为Map格式
         */
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("motd", motd);
            map.put("gameType", gameType);
            map.put("map", this.map);
            map.put("onlinePlayers", onlinePlayers);
            map.put("maxPlayers", maxPlayers);
            map.put("port", port);
            map.put("hostname", hostname);
            map.put("version", version);
            map.put("plugins", plugins);
            map.put("playerList", playerList);
            return map;
        }

        @Override
        public String toString() {
            return "ServerStatus{" +
                    "motd='" + motd + '\'' +
                    ", gameType='" + gameType + '\'' +
                    ", map='" + map + '\'' +
                    ", onlinePlayers=" + onlinePlayers +
                    ", maxPlayers=" + maxPlayers +
                    ", port=" + port +
                    ", hostname='" + hostname + '\'' +
                    ", version='" + version + '\'' +
                    ", plugins='" + plugins + '\'' +
                    ", playerList=" + playerList +
                    '}';
        }
    }
}