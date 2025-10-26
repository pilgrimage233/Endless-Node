package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.MasterNodes;
import cc.endmc.endlessnode.dto.TokenWithNodeInfo;
import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.service.MasterNodesService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class HomeController {

    private final AccessTokensService accessTokensService;
    private final MasterNodesService masterNodesService;

    /**
     * 获取所有Token列表（包含节点绑定信息）
     */
    @GetMapping("/tokens")
    public ResponseEntity<List<TokenWithNodeInfo>> getAllTokens() {
        List<AccessTokens> tokens = accessTokensService.list();
        
        // 转换为包含节点信息的DTO
        List<TokenWithNodeInfo> tokenWithNodeInfos = tokens.stream()
                .map(token -> {
                    // 查找对应的节点信息
                    MasterNodes masterNode = null;
                    if (token.getMasterId() != null) {
                        masterNode = masterNodesService.lambdaQuery()
                                .eq(MasterNodes::getSecretKey, token.getToken())
                                .one();
                    }
                    return new TokenWithNodeInfo(token, masterNode);
                })
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(tokenWithNodeInfos);
    }

    /**
     * 创建新的Token
     */
    @PostMapping("/tokens")
    public ResponseEntity<Map<String, Object>> createToken(@RequestBody Map<String, Object> request) {
        try {
            String scope = (String) request.get("scope");
            Integer expiresDays = (Integer) request.get("expiresDays");
            Boolean isPermanent = (Boolean) request.get("isPermanent");
            String remark = (String) request.get("remark");

            if (scope == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "缺少必要参数"));
            }

            // 自动获取第一个可用的主控端ID（默认使用ID为1的主控端）
            Integer masterId = 1; // 默认主控端ID

            // 创建新的访问令牌
            AccessTokens accessToken = new AccessTokens();
            accessToken.setToken(java.util.UUID.randomUUID().toString());
            accessToken.setMasterId(masterId);
            
            // 处理过期时间
            if (Boolean.TRUE.equals(isPermanent) || (expiresDays != null && expiresDays == -1)) {
                // 永久Token，设置为最大时间
                accessToken.setExpiresAt(new Date(Long.MAX_VALUE));
            } else if (expiresDays != null && expiresDays > 0) {
                // 普通Token，设置指定天数后过期
                accessToken.setExpiresAt(new Date(System.currentTimeMillis() + expiresDays * 24 * 60 * 60 * 1000L));
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "无效的有效期设置"));
            }
            
            accessToken.setScope(scope);
            accessToken.setRemark(remark); // 设置备注
            accessToken.setCreatedAt(new Date());

            accessTokensService.save(accessToken);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Token创建成功");
            response.put("token", accessToken);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "创建失败: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * 删除Token
     */
    @DeleteMapping("/tokens/{token}")
    public ResponseEntity<Map<String, Object>> deleteToken(@PathVariable String token) {
        try {
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            if (accessToken == null) {
                return ResponseEntity.status(404).body(Map.of("error", "Token不存在"));
            }

            accessTokensService.removeById(token);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Token删除成功");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "删除失败: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * 获取Token详情（包含节点绑定信息）
     */
    @GetMapping("/tokens/{token}")
    public ResponseEntity<Map<String, Object>> getToken(@PathVariable String token) {
        try {
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            if (accessToken == null) {
                return ResponseEntity.status(404).body(Map.of("error", "Token不存在"));
            }

            // 查找对应的节点信息
            MasterNodes masterNode = null;
            if (accessToken.getMasterId() != null) {
                masterNode = masterNodesService.lambdaQuery()
                        .eq(MasterNodes::getId, accessToken.getMasterId())
                        .one();
            }

            TokenWithNodeInfo tokenWithNodeInfo = new TokenWithNodeInfo(accessToken, masterNode);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("token", tokenWithNodeInfo);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "获取失败: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * 更新Token
     */
    @PutMapping("/tokens/{token}")
    public ResponseEntity<Map<String, Object>> updateToken(@PathVariable String token, @RequestBody Map<String, Object> request) {
        try {
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();

            if (accessToken == null) {
                return ResponseEntity.status(404).body(Map.of("error", "Token不存在"));
            }

            // 更新字段
            if (request.containsKey("scope")) {
                accessToken.setScope((String) request.get("scope"));
            }
            if (request.containsKey("expiresDays")) {
                Integer expiresDays = (Integer) request.get("expiresDays");
                accessToken.setExpiresAt(new Date(System.currentTimeMillis() + expiresDays * 24 * 60 * 60 * 1000L));
            }

            accessTokensService.updateById(accessToken);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Token更新成功");
            response.put("token", accessToken);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "更新失败: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * 首页路由
     */
    @GetMapping("/")
    public String home() {
        return "redirect:/index.html";
    }
}
