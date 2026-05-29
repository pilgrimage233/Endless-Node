package cc.endmc.endlessnode.config;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.AccessTokensService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.util.Date;
import java.util.Map;

/**
 * WebSocket 配置：消息代理 + 握手拦截 + STOMP CONNECT 认证。
 */
@Configuration
@EnableWebSocketMessageBroker
@RequiredArgsConstructor
@Slf4j
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final AccessTokensService accessTokensService;

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic", "/queue");
        registry.setApplicationDestinationPrefixes("/app");
        registry.setUserDestinationPrefix("/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws")
                .setAllowedOriginPatterns("*")
                .addInterceptors(new WebSocketHandshakeInterceptor(accessTokensService))
                .withSockJS();
    }

    /**
     * 注册 STOMP 入站通道拦截器，在 CONNECT 时强制校验 token。
     */
    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(new StompAuthChannelInterceptor(accessTokensService));
    }

    /**
     * WebSocket 握手拦截器：验证 header/query 中的 token。
     */
    private record WebSocketHandshakeInterceptor(
            AccessTokensService accessTokensService) implements HandshakeInterceptor {

        @Override
        public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                       WebSocketHandler wsHandler, Map<String, Object> attributes) {
            String token = request.getHeaders().getFirst(Node.Header.X_ENDLESS_TOKEN);
            if (token == null || token.isEmpty()) {
                String query = request.getURI().getQuery();
                if (query != null) {
                    for (String param : query.split("&")) {
                        if (param.startsWith("token=")) {
                            token = param.substring(6);
                            break;
                        }
                    }
                }
            }

            if (token != null && !token.isEmpty()) {
                AccessTokens at = accessTokensService.lambdaQuery()
                        .eq(AccessTokens::getToken, token).one();
                if (at == null || isExpired(at)) {
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return false;
                }
                attributes.put("token", token);
                attributes.put("masterId", at.getMasterId());
                attributes.put("masterUuid", at.getMasterUuid());
            }
            // 允许握手通过，STOMP CONNECT 阶段会再次校验
            return true;
        }

        @Override
        public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                   WebSocketHandler wsHandler, Exception exception) {
        }
    }

    /**
     * STOMP 入站拦截器：在 CONNECT 帧时强制校验 token，拒绝未认证连接。
     */
    private record StompAuthChannelInterceptor(AccessTokensService accessTokensService)
            implements ChannelInterceptor {

        @Override
        public Message<?> preSend(Message<?> message, MessageChannel channel) {
            StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
            if (accessor == null) return message;

            if (StompCommand.CONNECT.equals(accessor.getCommand())) {
                String token = accessor.getFirstNativeHeader(Node.Header.X_ENDLESS_TOKEN);
                if (token == null || token.isEmpty()) {
                    log.warn("STOMP CONNECT 被拒绝: 缺少 token");
                    return null; // 丢弃消息，拒绝连接
                }
                AccessTokens at = accessTokensService.lambdaQuery()
                        .eq(AccessTokens::getToken, token).one();
                if (at == null || isExpired(at)) {
                    log.warn("STOMP CONNECT 被拒绝: 无效或过期 token");
                    return null;
                }
                // 将认证信息存入 StompHeaderAccessor 的 session attributes
                accessor.getSessionAttributes().put("token", token);
                accessor.getSessionAttributes().put("masterId", at.getMasterId());
                accessor.getSessionAttributes().put("masterUuid", at.getMasterUuid());
                accessor.setUser(() -> at.getMasterUuid());
                log.debug("STOMP CONNECT 认证成功: masterUuid={}", at.getMasterUuid());
            }
            return message;
        }
    }

    private static boolean isExpired(AccessTokens at) {
        return at.getExpiresAt().getTime() != Long.MAX_VALUE && at.getExpiresAt().before(new Date());
    }
}
