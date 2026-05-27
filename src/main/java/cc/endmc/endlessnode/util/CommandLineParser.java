package cc.endmc.endlessnode.util;

import java.util.ArrayList;
import java.util.List;

/**
 * 简单的命令行解析器：将一行命令解析为 ProcessBuilder 的参数列表。
 * <p>
 * 支持单引号/双引号包裹；支持反斜杠转义（在引号内外均生效）。
 * 不支持 shell 运算符（如 &&、|、; 等），用于减少命令注入风险。
 */
public final class CommandLineParser {

    private CommandLineParser() {
    }

    public static List<String> parse(String commandLine) {
        if (commandLine == null) {
            throw new IllegalArgumentException("Command line cannot be null");
        }

        String input = commandLine.trim();
        if (input.isEmpty()) {
            throw new IllegalArgumentException("Command line cannot be empty");
        }

        if (containsControlChars(input)) {
            throw new IllegalArgumentException("Command line contains control characters");
        }

        List<String> args = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inSingleQuotes = false;
        boolean inDoubleQuotes = false;
        boolean escaping = false;

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);

            if (escaping) {
                current.append(c);
                escaping = false;
                continue;
            }

            if (c == '\\') {
                escaping = true;
                continue;
            }

            if (!inDoubleQuotes && c == '\'') {
                inSingleQuotes = !inSingleQuotes;
                continue;
            }

            if (!inSingleQuotes && c == '"') {
                inDoubleQuotes = !inDoubleQuotes;
                continue;
            }

            if (!inSingleQuotes && !inDoubleQuotes && Character.isWhitespace(c)) {
                if (current.length() > 0) {
                    args.add(current.toString());
                    current.setLength(0);
                }
                continue;
            }

            current.append(c);
        }

        if (escaping) {
            throw new IllegalArgumentException("Command line ends with escape character");
        }
        if (inSingleQuotes || inDoubleQuotes) {
            throw new IllegalArgumentException("Command line has unclosed quotes");
        }

        if (current.length() > 0) {
            args.add(current.toString());
        }

        if (args.isEmpty()) {
            throw new IllegalArgumentException("No command parsed");
        }

        return args;
    }

    private static boolean containsControlChars(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 0 || c == '\n' || c == '\r' || c == '\t') {
                return true;
            }
        }
        return false;
    }
}

