package cc.endmc.endlessnode.config;

import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.service.AccessTokensService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Date;

/**
 * Token验证拦截器
 * 除了注册接口外，所有接口都需要验证token
 */
@Component
@RequiredArgsConstructor
public class TokenInterceptor implements HandlerInterceptor {

    private static final String TOKEN_HEADER = "X-Endless-Token";
    private final AccessTokensService accessTokensService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 获取请求路径
        //String requestURI = request.getRequestURI();

        // 如果是注册接口，直接放行
        //if (requestURI.equals("/api/auth/register")) {
        //    return true;
        //}

        // 从请求头中获取token
        //String token = "74ba5eea-2bd5-4ccc-bcf6-bf43da7a8981";
        String token = request.getHeader(TOKEN_HEADER);

        // 如果token为空，返回401未授权
        if (token == null || token.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Missing token\"}");
            return false;
        }

        // 验证token
        AccessTokens accessToken = accessTokensService.lambdaQuery()
                .eq(AccessTokens::getToken, token)
                .one();

        // 如果token不存在或已过期，返回401未授权
        if (accessToken == null || accessToken.getExpiresAt().before(new Date())) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
            return false;
        }

        // token有效，放行
        return true;
    }
} 