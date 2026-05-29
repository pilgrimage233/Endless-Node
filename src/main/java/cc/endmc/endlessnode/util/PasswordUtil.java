package cc.endmc.endlessnode.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 密码加密工具类
 * 使用BCrypt算法进行密码加密和验证
 */
public class PasswordUtil {
    
    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    
    /**
     * 加密密码
     * @param rawPassword 原始密码
     * @return 加密后的密码
     */
    public static String encode(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }
    
    /**
     * 验证密码
     * @param rawPassword 原始密码
     * @param encodedPassword 加密后的密码
     * @return 是否匹配
     */
    public static boolean matches(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
    
    /**
     * 生成随机密码（12位，包含大小写字母和数字）
     * @return 随机密码明文
     */
    public static String generateRandomPassword() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[9];
        random.nextBytes(bytes);
        String raw = Base64.getEncoder().encodeToString(bytes);
        // 确保包含大小写和数字，替换特殊字符
        return raw.replace("+", "A").replace("/", "B").replace("=", "C");
    }

    /**
     * 生成随机密码并返回加密值
     * @return 数组: [0] = 明文密码, [1] = BCrypt加密后密码
     */
    public static String[] generateRandomAdminPassword() {
        String raw = generateRandomPassword();
        return new String[]{raw, encode(raw)};
    }
}
