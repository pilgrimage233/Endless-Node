package cc.endmc.endlessnode.config;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.AccessTokensService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.util.Date;
import java.util.Map;

/**
 * WebSocket配置类
 * 启用WebSocket支持，配置消息代理和端点
 */
@Configuration
@EnableWebSocketMessageBroker
@RequiredArgsConstructor
@Slf4j
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final AccessTokensService accessTokensService;

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        // 设置消息代理的前缀，客户端订阅消息的前缀
        registry.enableSimpleBroker("/topic", "/queue");
        // 设置客户端发送消息的前缀
        registry.setApplicationDestinationPrefixes("/app");
        // 设置用户目标前缀，用于convertAndSendToUser
        registry.setUserDestinationPrefix("/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // 注册STOMP端点，客户端通过这个端点连接WebSocket
        registry.addEndpoint("/ws")
                .setAllowedOriginPatterns("*") // 使用allowedOriginPatterns代替allowedOrigins，支持credentials
                .addInterceptors(new WebSocketHandshakeInterceptor(accessTokensService))
                .withSockJS(); // 启用SockJS支持，提供更好的浏览器兼容性
    }

    /**
     * WebSocket握手拦截器
     * 在WebSocket握手阶段验证token
     */
    private record WebSocketHandshakeInterceptor(
            AccessTokensService accessTokensService) implements HandshakeInterceptor {

        @Override
        public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                       WebSocketHandler wsHandler, Map<String, Object> attributes) {

            log.debug("WebSocket握手开始: {}", request.getURI());

            // 获取token头（主要用于原生WebSocket）
            String token = request.getHeaders().getFirst(Node.Header.X_ENDLESS_TOKEN);

            // 对于SockJS，token可能通过查询参数传递
            if (token == null || token.isEmpty()) {
                String query = request.getURI().getQuery();
                if (query != null) {
                    String[] params = query.split("&");
                    for (String param : params) {
                        if (param.startsWith("token=")) {
                            token = param.substring(6);
                            break;
                        }
                    }
                }
            }

            // 对于SockJS握手阶段，如果没有token，我们允许握手通过
            // 真正的认证将在STOMP CONNECT消息中进行
            if (token != null && !token.isEmpty()) {
                // 验证token
                AccessTokens accessToken = accessTokensService.lambdaQuery()
                        .eq(AccessTokens::getToken, token)
                        .one();

                if (accessToken == null) {
                    log.warn("WebSocket握手失败: 无效token");
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return false;
                }

                // 检查token是否过期
                if (accessToken.getExpiresAt().getTime() != Long.MAX_VALUE &&
                        accessToken.getExpiresAt().before(new Date())) {
                    log.warn("WebSocket握手失败: token已过期");
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return false;
                }

                // 将token信息保存到WebSocket会话属性中
                attributes.put("token", token);
                attributes.put("masterId", accessToken.getMasterId());
                attributes.put("masterUuid", accessToken.getMasterUuid());
                attributes.put("obj", accessToken);

                log.debug("WebSocket握手成功: masterId={}", accessToken.getMasterId());
            } else {
                log.debug("WebSocket握手通过（无token验证，将在STOMP层验证）");
            }

            return true;
        }

        @Override
        public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                   WebSocketHandler wsHandler, Exception exception) {
            if (exception != null) {
                log.error("WebSocket握手异常", exception);
            } else {
                log.debug("WebSocket握手完成");
            }
        }
    }
} 