package cc.endmc.endlessnode.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 安全路径工具类：将用户输入的路径安全地限制在指定根目录下。
 * <p>
 * 主要用于防御路径穿越（../）与符号链接逃逸。
 */
public final class SafePaths {

    private SafePaths() {
    }

    /**
     * 将用户输入路径解析到 root 下，并确保最终目标仍位于 root 内。
     *
     * @param root      根目录（允许为相对路径）
     * @param userInput 用户输入（可为空；可为相对或绝对路径）
     * @return 规范化后的路径（绝对路径）
     */
    public static Path safeJoin(Path root, String userInput) {
        if (root == null) {
            throw new IllegalArgumentException("root cannot be null");
        }

        if (userInput != null && userInput.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Path contains NUL byte");
        }

        Path rootNormalized = root.toAbsolutePath().normalize();
        Path candidate = (userInput == null || userInput.trim().isEmpty())
                ? rootNormalized
                : rootNormalized.resolve(userInput.trim()).normalize();

        if (!candidate.startsWith(rootNormalized)) {
            throw new IllegalArgumentException("Path escapes root directory");
        }

        return candidate;
    }

    /**
     * 进一步对存在的路径进行 realPath 校验，防止符号链接逃逸。
     * <p>
     * 如果目标不存在，则对其最近的存在祖先目录做 realPath 校验。
     */
    public static Path verifyRealPathWithinRoot(Path root, Path candidate) throws IOException {
        if (root == null || candidate == null) {
            throw new IllegalArgumentException("root/candidate cannot be null");
        }

        Path rootReal = toRealPathIfExists(root.toAbsolutePath().normalize());
        Path current = candidate.toAbsolutePath().normalize();

        Path existing = current;
        while (existing != null && !Files.exists(existing)) {
            existing = existing.getParent();
        }

        if (existing != null) {
            Path existingReal = existing.toRealPath();
            if (!existingReal.startsWith(rootReal)) {
                throw new IllegalArgumentException("Path escapes root directory (symlink)");
            }
        } else {
            // root 不存在时，回退到纯路径检查
            if (!current.startsWith(rootReal)) {
                throw new IllegalArgumentException("Path escapes root directory");
            }
        }

        return current;
    }

    private static Path toRealPathIfExists(Path path) throws IOException {
        if (Files.exists(path)) {
            return path.toRealPath();
        }
        return path;
    }
}

