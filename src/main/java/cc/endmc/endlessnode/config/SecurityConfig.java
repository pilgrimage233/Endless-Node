package cc.endmc.endlessnode.config;

import cc.endmc.endlessnode.common.TokenCache;
import cc.endmc.endlessnode.domain.AccessTokens;
import cc.endmc.endlessnode.manage.Node;
import cc.endmc.endlessnode.service.AccessTokensService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

/**
 * Spring Security 配置：替代原有 TokenInterceptor，实现标准化认证与安全响应头。
 * <p>
 * - /api/auth/** 与静态资源：放行
 * - /api/servers/**、/api/files/**、/api/system/**、/api/java-env/**：要求 X-Endless-Token
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AccessTokensService accessTokensService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .headers(headers -> headers
                        .contentTypeOptions(Customizer.withDefaults())
                        .frameOptions(frame -> frame.sameOrigin())
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Unauthorized\"}");
                }))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/index.html",
                                "/login.html",
                                "/tokens.html",
                                "/change-password.html",
                                "/websocket-test.html",
                                "/actuator/health",
                                "/actuator/info",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/static/**",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/ws/**"
                        ).permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/tokens/**").permitAll()
                        .requestMatchers("/system/info").permitAll()
                        .requestMatchers(
                                "/api/servers/**",
                                "/api/files/**",
                                "/api/system/**",
                                "/api/java-env/**",
                                "/api/manage/**"
                        ).authenticated()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .anyRequest().denyAll()
                )
                .addFilterBefore(new EndlessTokenAuthenticationFilter(accessTokensService), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Slf4j
    private static final class EndlessTokenAuthenticationFilter extends OncePerRequestFilter {

        private final AccessTokensService accessTokensService;

        private EndlessTokenAuthenticationFilter(AccessTokensService accessTokensService) {
            this.accessTokensService = accessTokensService;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {

            if (!requiresToken(request)) {
                filterChain.doFilter(request, response);
                return;
            }

            String token = request.getHeader(Node.Header.X_ENDLESS_TOKEN);
            if (!StringUtils.hasText(token)) {
                unauthorized(response, "Missing token");
                return;
            }

            AccessTokens accessToken = getAccessToken(token);
            if (accessToken == null || isTokenExpired(accessToken)) {
                unauthorized(response, "Invalid or expired token");
                return;
            }

            Authentication authentication = buildAuthentication(accessToken);
            org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);
        }

        private boolean requiresToken(HttpServletRequest request) {
            String uri = request.getRequestURI();
            if (uri == null) {
                return false;
            }
            return uri.startsWith("/api/servers/")
                    || uri.equals("/api/servers")
                    || uri.startsWith("/api/files/")
                    || uri.equals("/api/files")
                    || uri.startsWith("/api/system/")
                    || uri.equals("/api/system")
                    || uri.startsWith("/api/java-env/")
                    || uri.equals("/api/java-env")
                    || uri.startsWith("/api/manage/");
        }

        private AccessTokens getAccessToken(String token) {
            // get() 内部已做过期检查，过期时返回 null
            AccessTokens cached = TokenCache.get(token);
            if (cached != null) {
                return cached;
            }
            AccessTokens accessToken = accessTokensService.lambdaQuery()
                    .eq(AccessTokens::getToken, token)
                    .one();
            if (accessToken != null) {
                TokenCache.put(token, accessToken);
            }
            return accessToken;
        }

        private boolean isTokenExpired(AccessTokens accessToken) {
            return accessToken.getExpiresAt().getTime() != Long.MAX_VALUE &&
                    accessToken.getExpiresAt().before(new Date());
        }

        private Authentication buildAuthentication(AccessTokens accessToken) {
            String principal = accessToken.getMasterUuid() != null ? accessToken.getMasterUuid() : String.valueOf(accessToken.getMasterId());
            Collection<GrantedAuthority> authorities = parseAuthorities(accessToken.getScope());
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal, null, authorities);
            authentication.setDetails(accessToken);
            return authentication;
        }

        private Collection<GrantedAuthority> parseAuthorities(String scope) {
            if (!StringUtils.hasText(scope)) {
                return List.of();
            }
            String[] parts = scope.split("[,\\s]+");
            List<GrantedAuthority> list = new ArrayList<>();
            for (String part : parts) {
                String s = part == null ? "" : part.trim();
                if (!s.isEmpty()) {
                    // 统一加前缀，便于后续权限分级（不改变现有接口逻辑）
                    list.add(new SimpleGrantedAuthority("SCOPE_" + s.toUpperCase(Locale.ROOT)));
                }
            }
            return list;
        }

        private void unauthorized(HttpServletResponse response, String message) throws IOException {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"" + message.replace("\"", "") + "\"}");
        }
    }
}
