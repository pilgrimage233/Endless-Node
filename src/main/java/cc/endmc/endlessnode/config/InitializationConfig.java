package cc.endmc.endlessnode.config;

import cc.endmc.endlessnode.common.TokenCache;
import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.service.AccessTokensService;
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

    @Bean
    public CommandLineRunner initializeOnStartup() {
        return args -> {
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
        };


    }
}