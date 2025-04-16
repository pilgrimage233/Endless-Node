package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.MasterNodes;
import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.service.MasterNodesService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final MasterNodesService masterNodesService;
    private final AccessTokensService accessTokensService;

    @Value("${node.version}")
    private String version;

    /**
     * 注册主控端
     *
     * @param request 包含IP地址、版本、UUID（可选）和节点端生成的永久token秘钥的请求
     * @return 注册结果
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> request) {
        String ipAddress = request.get("ipAddress");
        String version = request.get("version");
        String secretKey = request.get("secretKey");
        String uuid = request.get("uuid"); // 可选参数，用于重新注册

        if (ipAddress == null || secretKey == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "缺少必要参数"));
        }

        // 如果提供了UUID，尝试查找并更新现有节点
        if (uuid != null) {
            MasterNodes existingNode = masterNodesService.lambdaQuery()
                    .eq(MasterNodes::getUuid, uuid)
                    .eq(MasterNodes::getSecretKey, secretKey)
                    .one();

            if (existingNode != null) {
                // 更新节点信息
                existingNode.setIpAddress(ipAddress);
                if (version != null) {
                    existingNode.setVersion(version);
                }
                existingNode.setLastCommunication(new Date());
                existingNode.setIsDeleted(0); // 确保节点状态为正常
                masterNodesService.updateById(existingNode);

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "节点重新注册成功");
                response.put("nodeId", existingNode.getId());
                response.put("nodeUuid", existingNode.getUuid());
                response.put("version", existingNode.getVersion());

                // 获取主机系统
                String osType = System.getProperty("os.name");
                response.put("osType", osType);

                return ResponseEntity.ok(response);
            }
        }

        // 检查是否已存在相同IP和节点token的主控端
        MasterNodes existingNode = masterNodesService.lambdaQuery()
                .eq(MasterNodes::getIpAddress, ipAddress)
                .eq(MasterNodes::getSecretKey, secretKey)
                .eq(MasterNodes::getIsDeleted, 0)
                .one();

        if (existingNode != null) {
            // 更新最后通信时间
            existingNode.setLastCommunication(new Date());
            if (version != null) {
                existingNode.setVersion(version);
            }
            masterNodesService.updateById(existingNode);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "节点已注册");
            response.put("nodeId", existingNode.getId());
            response.put("nodeUuid", existingNode.getUuid());
            response.put("version", existingNode.getVersion());

            // 获取主机系统
            String osType = System.getProperty("os.name");
            response.put("osType", osType);

            return ResponseEntity.ok(response);
        }

        // 创建新的主控端记录
        MasterNodes newNode = new MasterNodes();
        newNode.setUuid(UUID.randomUUID().toString());
        newNode.setVersion(version != null ? version : "1.0.0");  // 主控端版本
        newNode.setSecretKey(secretKey);
        newNode.setIpAddress(ipAddress);
        newNode.setRegisteredAt(new Date());
        newNode.setLastCommunication(new Date());
        newNode.setIsDeleted(0);
        newNode.setProtocolVersion("1.0");

        masterNodesService.save(newNode);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "节点注册成功");
        response.put("nodeUuid", newNode.getUuid());
        response.put("version", newNode.getVersion());

        // 获取主机系统
        String osType = System.getProperty("os.name");
        response.put("osType", osType);

        return ResponseEntity.ok(response);
    }

    /**
     * 注销主控端
     *
     * @param request 包含UUID和节点端生成的永久token秘钥的请求
     * @return 注销结果
     */
    @PostMapping("/unregister")
    public ResponseEntity<Map<String, Object>> unregister(@RequestBody Map<String, String> request) {
        String uuid = request.get("uuid");
        String secretKey = request.get("secretKey");

        if (uuid == null || secretKey == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "缺少必要参数"));
        }

        // 检查是否存在匹配的主控端记录
        MasterNodes existingNode = masterNodesService.lambdaQuery()
                .eq(MasterNodes::getUuid, uuid)
                .eq(MasterNodes::getSecretKey, secretKey)
                .eq(MasterNodes::getIsDeleted, 0)
                .one();

        if (existingNode == null) {
            return ResponseEntity.status(404).body(Map.of("error", "节点未找到或已注销"));
        }

        // 标记为已删除
        existingNode.setIsDeleted(1);
        existingNode.setLastCommunication(new Date());
        masterNodesService.updateById(existingNode);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "节点注销成功");
        response.put("nodeId", existingNode.getId());

        return ResponseEntity.ok(response);
    }

    /**
     * 生成访问令牌
     *
     * @param masterId 主控端ID
     * @return 访问令牌
     */
    private AccessTokens generateAccessToken(Integer masterId) {
        // 生成JWT令牌
        String token = UUID.randomUUID().toString();

        // 创建访问令牌记录
        AccessTokens accessToken = new AccessTokens();
        accessToken.setToken(token);
        accessToken.setMasterId(masterId);
        accessToken.setExpiresAt(new Date(System.currentTimeMillis() + 7 * 24 * 60 * 60 * 1000)); // 7天后过期
        accessToken.setScope("SERVER_CONTROL,FILE_MANAGE");
        accessToken.setCreatedAt(new Date());

        accessTokensService.save(accessToken);

        return accessToken;
    }

    /**
     * 验证令牌
     *
     * @param token 访问令牌
     * @return 验证结果
     */
    @GetMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyToken(@RequestParam String token) {
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        if (accessToken == null) {
            return ResponseEntity.status(401).body(Map.of("valid", false, "message", "Invalid token"));
        }

        // 检查令牌是否过期
        if (accessToken.getExpiresAt().before(new Date())) {
            return ResponseEntity.status(401).body(Map.of("valid", false, "message", "Token expired"));
        }

        return ResponseEntity.ok(Map.of(
                "valid", true,
                "masterId", accessToken.getMasterId(),
                "scope", accessToken.getScope(),
                "expiresAt", accessToken.getExpiresAt()
        ));
    }
} 