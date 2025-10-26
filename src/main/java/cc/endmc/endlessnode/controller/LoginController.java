package cc.endmc.endlessnode.controller;

import cc.endmc.endlessnode.util.PasswordUtil;
import cc.endmc.endlessnode.domain.Users;
import cc.endmc.endlessnode.service.UsersService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class LoginController {

    private final UsersService usersService;

    /**
     * 用户登录
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request, 
                                                    HttpServletRequest httpRequest, 
                                                    HttpServletResponse httpResponse) {
        String username = request.get("username");
        String password = request.get("password");

        if (username == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "用户名和密码不能为空"));
        }

        // 查找用户
        Users user = usersService.lambdaQuery()
                .eq(Users::getUsername, username)
                .eq(Users::getEnabled, 1)
                .one();

        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "用户名或密码错误"));
        }

        // 使用BCrypt验证密码
        if (!PasswordUtil.matches(password, user.getPassword())) {
            return ResponseEntity.status(401).body(Map.of("error", "用户名或密码错误"));
        }

        // 更新最后登录时间
        user.setLastLogin(new Date());
        usersService.updateById(user);

        // 创建会话
        HttpSession session = httpRequest.getSession(true);
        session.setAttribute("user", user);
        session.setAttribute("userId", user.getId());
        session.setAttribute("username", user.getUsername());
        session.setAttribute("role", user.getRole());

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "登录成功");
        response.put("user", Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "role", user.getRole(),
                "firstLogin", user.getFirstLogin()
        ));
        
        // 检查是否首次登录
        if (user.getFirstLogin() != null && user.getFirstLogin() == 1) {
            response.put("requirePasswordChange", true);
            response.put("message", "首次登录，请修改密码");
        }

        return ResponseEntity.ok(response);
    }

    /**
     * 用户登出
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "登出成功");

        return ResponseEntity.ok(response);
    }

    /**
     * 获取当前用户信息
     */
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getCurrentUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "未登录"));
        }

        Users user = (Users) session.getAttribute("user");
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("user", Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "role", user.getRole(),
                "lastLogin", user.getLastLogin()
        ));

        return ResponseEntity.ok(response);
    }

    /**
     * 检查登录状态
     */
    @GetMapping("/check")
    public ResponseEntity<Map<String, Object>> checkLogin(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        boolean isLoggedIn = session != null && session.getAttribute("user") != null;

        Map<String, Object> response = new HashMap<>();
        response.put("loggedIn", isLoggedIn);
        if (isLoggedIn) {
            response.put("username", session.getAttribute("username"));
            response.put("role", session.getAttribute("role"));
        }

        return ResponseEntity.ok(response);
    }

    /**
     * 修改密码
     */
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, Object>> changePassword(@RequestBody Map<String, String> request, 
                                                             HttpServletRequest httpRequest) {
        String oldPassword = request.get("oldPassword");
        String newPassword = request.get("newPassword");
        String confirmPassword = request.get("confirmPassword");

        if (oldPassword == null || newPassword == null || confirmPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "缺少必要参数"));
        }

        if (!newPassword.equals(confirmPassword)) {
            return ResponseEntity.badRequest().body(Map.of("error", "新密码和确认密码不匹配"));
        }

        if (newPassword.length() < 6) {
            return ResponseEntity.badRequest().body(Map.of("error", "新密码长度不能少于6位"));
        }

        // 获取当前用户
        HttpSession session = httpRequest.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "未登录"));
        }

        Users currentUser = (Users) session.getAttribute("user");
        
        // 验证旧密码
        if (!PasswordUtil.matches(oldPassword, currentUser.getPassword())) {
            return ResponseEntity.status(401).body(Map.of("error", "原密码错误"));
        }

        // 更新密码
        currentUser.setPassword(PasswordUtil.encode(newPassword));
        currentUser.setFirstLogin(0); // 标记为非首次登录
        usersService.updateById(currentUser);

        // 更新Session中的用户信息
        session.setAttribute("user", currentUser);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "密码修改成功");

        return ResponseEntity.ok(response);
    }

    /**
     * 强制修改密码（首次登录）
     */
    @PostMapping("/force-change-password")
    public ResponseEntity<Map<String, Object>> forceChangePassword(@RequestBody Map<String, String> request, 
                                                                 HttpServletRequest httpRequest) {
        String newPassword = request.get("newPassword");
        String confirmPassword = request.get("confirmPassword");

        if (newPassword == null || confirmPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "缺少必要参数"));
        }

        if (!newPassword.equals(confirmPassword)) {
            return ResponseEntity.badRequest().body(Map.of("error", "新密码和确认密码不匹配"));
        }

        if (newPassword.length() < 6) {
            return ResponseEntity.badRequest().body(Map.of("error", "新密码长度不能少于6位"));
        }

        // 获取当前用户
        HttpSession session = httpRequest.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "未登录"));
        }

        Users currentUser = (Users) session.getAttribute("user");
        
        // 检查是否真的是首次登录
        if (currentUser.getFirstLogin() == null || currentUser.getFirstLogin() != 1) {
            return ResponseEntity.badRequest().body(Map.of("error", "不是首次登录，请使用普通修改密码功能"));
        }

        // 更新密码
        currentUser.setPassword(PasswordUtil.encode(newPassword));
        currentUser.setFirstLogin(0); // 标记为非首次登录
        usersService.updateById(currentUser);

        // 更新Session中的用户信息
        session.setAttribute("user", currentUser);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "密码设置成功");

        return ResponseEntity.ok(response);
    }
}
