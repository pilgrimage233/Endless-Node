package cc.endmc.endlessnode.util;

import java.util.Collections;
import java.util.Locale;
import java.util.Set;

/**
 * 命令限制与输入净化工具。
 */
public final class CommandRestrictions {

    private static final int MAX_CONSOLE_COMMAND_LENGTH = 1024;

    private CommandRestrictions() {
    }

    /**
     * 校验 Minecraft 控制台命令，禁止包含换行/控制字符，并支持拦截敏感命令。
     *
     * @param command         原始命令
     * @param blockedCommands 被拦截的敏感命令（不含前导 /，小写）
     * @return 规范化后的命令（trim 后）
     */
    public static String sanitizeMinecraftConsoleCommand(String command, Set<String> blockedCommands) {
        if (command == null) {
            throw new IllegalArgumentException("命令不能为空");
        }
        String trimmed = command.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("命令不能为空");
        }
        if (trimmed.length() > MAX_CONSOLE_COMMAND_LENGTH) {
            throw new IllegalArgumentException("命令过长");
        }
        if (containsControlChars(trimmed)) {
            throw new IllegalArgumentException("命令包含非法控制字符");
        }

        Set<String> blocked = blockedCommands == null ? Collections.emptySet() : blockedCommands;
        String commandName = extractCommandName(trimmed);
        if (commandName != null && blocked.contains(commandName)) {
            throw new IllegalArgumentException("敏感命令已被限制: " + commandName);
        }

        return trimmed;
    }

    /**
     * Windows 下执行自定义启动脚本时，会通过 cmd /c 运行，因此必须过滤 cmd 元字符。
     */
    public static void validateWindowsCmdScript(String script) {
        if (script == null) {
            throw new IllegalArgumentException("脚本不能为空");
        }
        String trimmed = script.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("脚本不能为空");
        }
        if (containsControlChars(trimmed)) {
            throw new IllegalArgumentException("脚本包含非法控制字符");
        }
        // 常见 cmd 元字符：& | < > ^ %
        if (trimmed.matches(".*[&|<>^%].*")) {
            throw new IllegalArgumentException("脚本包含不允许的字符");
        }
    }

    private static boolean containsControlChars(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 0 || c == '\n' || c == '\r') {
                return true;
            }
        }
        return false;
    }

    private static String extractCommandName(String command) {
        String s = command;
        if (s.startsWith("/")) {
            s = s.substring(1);
        }
        s = s.trim();
        if (s.isEmpty()) {
            return null;
        }
        int space = s.indexOf(' ');
        String name = (space >= 0) ? s.substring(0, space) : s;
        return name.toLowerCase(Locale.ROOT);
    }
}

