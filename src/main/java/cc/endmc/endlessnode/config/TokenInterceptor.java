package cc.endmc.endlessnode.config;

import cc.endmc.endlessnode.common.TokenCache;
import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.service.AccessTokensService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Date;

/**
 * 双重认证拦截器
 * 支持两种认证方式：
 * 1. Web管理界面：Session认证
 * 2. 节点API操作：Token认证
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenInterceptor implements HandlerInterceptor {

    private static final String TOKEN_HEADER = "X-Endless-Token";
    private final AccessTokensService accessTokensService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestURI = request.getRequestURI();

        // 调试日志
        log.debug("拦截器处理请求: {}", requestURI);

        // 1. 完全放行的路径（不需要任何认证）
        if (isPublicPath(requestURI)) {
            log.debug("公开路径，直接放行: {}", requestURI);
            return true;
        }

        // 2. Web管理界面路径（需要Session认证）
        if (isWebManagementPath(requestURI)) {
            return handleWebAuthentication(request, response);
        }

        // 3. 节点API路径（需要Token认证）
        if (isNodeApiPath(requestURI)) {
            return handleTokenAuthentication(request, response);
        }

        // 4. 其他路径默认拒绝
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"Unauthorized access\"}");
        return false;
    }

    /**
     * 判断是否为公开路径（不需要认证）
     */
    private boolean isPublicPath(String requestURI) {
        boolean isPublic = requestURI.startsWith("/api/auth/login") ||
                requestURI.startsWith("/api/auth/logout") ||
                requestURI.startsWith("/api/auth/check") ||
                requestURI.startsWith("/api/auth/register") ||
                requestURI.startsWith("/api/auth/verify") ||
                requestURI.startsWith("/api/auth/unregister") ||
                requestURI.startsWith("/login.html") ||
                requestURI.startsWith("/index.html") ||
                requestURI.startsWith("/static/") ||
                requestURI.equals("/") ||
                requestURI.startsWith("/css/") ||
                requestURI.startsWith("/js/") ||
                requestURI.startsWith("/images/");

        log.debug("路径检查: {} -> 是否公开: {}", requestURI, isPublic);
        return isPublic;
    }

    /**
     * 判断是否为Web管理界面路径（需要Session认证）
     */
    private boolean isWebManagementPath(String requestURI) {
        return requestURI.startsWith("/api/tokens") ||
                requestURI.startsWith("/api/user");
    }

    /**
     * 判断是否为节点API路径（需要Token认证）
     */
    private boolean isNodeApiPath(String requestURI) {
        return requestURI.startsWith("/api/server") ||
                requestURI.startsWith("/api/file") ||
                requestURI.startsWith("/api/websocket") ||
                requestURI.startsWith("/api/node") ||
                requestURI.startsWith("/api/system");
    }

    /**
     * 处理Web管理界面的Session认证
     */
    private boolean handleWebAuthentication(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute("user") != null) {
            // 用户已登录，放行
            return true;
        }

        // 未登录，重定向到登录页
        response.sendRedirect("/login.html");
        return false;
    }

    /**
     * 处理节点API的Token认证
     */
    private boolean handleTokenAuthentication(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String token = request.getHeader(TOKEN_HEADER);
        if (token == null || token.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Missing token\"}");
            return false;
        }

        // 验证token
        AccessTokens accessToken = getAccessToken(token);
        if (accessToken == null || isTokenExpired(accessToken)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
            return false;
        }

        // Token有效，放行
        return true;
    }

    /**
     * 获取访问令牌
     */
    private AccessTokens getAccessToken(String token) {
        if (TokenCache.containsKey(token)) {
            return TokenCache.get(token);
        } else {
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();
            if (accessToken != null) {
                TokenCache.put(token, accessToken);
            }
            return accessToken;
        }
    }

    /**
     * 检查Token是否过期
     */
    private boolean isTokenExpired(AccessTokens accessToken) {
        return accessToken.getExpiresAt().getTime() != Long.MAX_VALUE &&
                accessToken.getExpiresAt().before(new Date());
    }
} 