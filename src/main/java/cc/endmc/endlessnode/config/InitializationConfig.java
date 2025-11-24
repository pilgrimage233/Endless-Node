package cc.endmc.endlessnode.config;

import cc.endmc.endlessnode.common.TokenCache;
import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.domain.Users;
import cc.endmc.endlessnode.service.AccessTokensService;
import cc.endmc.endlessnode.service.UsersService;
import cc.endmc.endlessnode.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Date;
import java.util.List;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class InitializationConfig {

    private final AccessTokensService accessTokensService;
    private final UsersService usersService;
    private final InitConfigService initConfigService;

    @Bean
    public CommandLineRunner initializeOnStartup() {
        return args -> {
            // 首先初始化配置文件
            log.info("初始化配置文件...");
            initConfigService.initializeConfigs();
            
            log.info("Checking if initialization is needed...");

            // 检查是否已存在访问令牌
            final List<AccessTokens> list = accessTokensService.list();

            if (list.isEmpty()) {
                log.info("秘钥不存在，创建新的秘钥...");

                // 创建永久的访问令牌
                AccessTokens permanentToken = new AccessTokens();
                permanentToken.setToken(UUID.randomUUID().toString());
                permanentToken.setMasterId(1); // 默认主控端ID
                permanentToken.setExpiresAt(new Date(Long.MAX_VALUE)); // 设置为最大时间，相当于永不过期
                permanentToken.setScope("SERVER_CONTROL,FILE_MANAGE");
                permanentToken.setCreatedAt(new Date());

                accessTokensService.save(permanentToken);

                log.info("秘钥创建成功: {}", permanentToken.getToken());
            } else {
                log.info("秘钥存在: {}", list.get(0).getToken());
            }
            // token缓存
            accessTokensService.list().forEach(accessToken -> {
                TokenCache.put(accessToken.getToken(), accessToken);
            });
            log.info("Token缓存初始化完成，当前缓存数量: {}", TokenCache.size());

            // 检查并初始化默认管理员用户
            initializeDefaultAdmin();
        };
    }

    /**
     * 初始化默认管理员用户
     */
    private void initializeDefaultAdmin() {
        try {
            Users adminUser = usersService.lambdaQuery()
                    .eq(Users::getUsername, "admin")
                    .one();

            if (adminUser == null) {
                log.info("创建默认管理员用户...");
                adminUser = new Users();
                adminUser.setUsername("admin");
                adminUser.setPassword(PasswordUtil.getDefaultAdminPassword());
                adminUser.setRole("ADMIN");
                adminUser.setEnabled(1);
                adminUser.setFirstLogin(1); // 标记为首次登录
                adminUser.setCreatedAt(new Date());
                usersService.save(adminUser);
                log.info("默认管理员用户创建成功");
            } else {
                // 检查密码是否需要更新（如果密码不是BCrypt格式）
                if (!adminUser.getPassword().startsWith("$2a$")) {
                    log.info("更新管理员用户密码为BCrypt格式...");
                    adminUser.setPassword(PasswordUtil.getDefaultAdminPassword());
                    usersService.updateById(adminUser);
                    log.info("管理员用户密码更新成功");
                }
            }
        } catch (Exception e) {
            log.error("初始化默认管理员用户失败", e);
        }
    }
}