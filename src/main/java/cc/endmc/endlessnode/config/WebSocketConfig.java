package cc.endmc.endlessnode.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * WebSocket配置类
 * 启用WebSocket支持，配置消息代理和端点
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        // 设置消息代理的前缀，客户端订阅消息的前缀
        registry.enableSimpleBroker("/topic");
        // 设置客户端发送消息的前缀
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // 注册STOMP端点，客户端通过这个端点连接WebSocket
        registry.addEndpoint("/ws")
                .setAllowedOrigins("*") // 允许所有来源，生产环境中应该限制
                .withSockJS(); // 启用SockJS支持，提供更好的浏览器兼容性
    }
} 