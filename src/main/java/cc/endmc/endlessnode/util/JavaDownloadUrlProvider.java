package cc.endmc.endlessnode.util;

import lombok.extern.slf4j.Slf4j;

/**
 * Java下载URL提供工具类
 * 负责为不同的Java供应商和版本提供下载链接
 */
@Slf4j
public class JavaDownloadUrlProvider {

    /**
     * 获取Java下载URL
     *
     * @param version Java版本 (8, 11, 17, 21)
     * @param vendor  供应商 (Adoptium, Zulu, Corretto, Microsoft, GraalVM)
     * @param os      操作系统
     * @param arch    架构
     * @return 下载URL，如果不支持则返回null
     */
    public static String getDownloadUrl(String version, String vendor, String os, String arch) {
        if ("Adoptium".equalsIgnoreCase(vendor) || "Temurin".equalsIgnoreCase(vendor)) {
            return getAdoptiumUrl(version, os, arch);
        } else if ("Zulu".equalsIgnoreCase(vendor)) {
            return getZuluUrl(version, os, arch);
        } else if ("Corretto".equalsIgnoreCase(vendor) || "Amazon".equalsIgnoreCase(vendor)) {
            return getCorrettoUrl(version, os, arch);
        } else if ("Microsoft".equalsIgnoreCase(vendor)) {
            return getMicrosoftUrl(version, os, arch);
        } else if ("GraalVM".equalsIgnoreCase(vendor)) {
            return getGraalVMUrl(version, os, arch);
        }
        // 默认使用Adoptium
        return getAdoptiumUrl(version, os, arch);
    }

    /**
     * 获取Adoptium (Eclipse Temurin) 下载URL
     */
    private static String getAdoptiumUrl(String version, String os, String arch) {
        String osType = normalizeOsForAdoptium(os);
        if (osType == null) return null;

        return String.format(
                "https://api.adoptium.net/v3/binary/latest/%s/ga/%s/%s/jdk/hotspot/normal/eclipse?project=jdk",
                version, osType, arch
        );
    }

    /**
     * 获取Azul Zulu下载URL
     */
    private static String getZuluUrl(String version, String os, String arch) {
        String osType = normalizeOsForZulu(os);
        String archType = normalizeArchForZulu(arch);
        if (osType == null || archType == null) return null;

        return switch (version) {
            case "8" -> getZuluUrlForVersion("8.80.0.17", "8.0.422", osType, archType);
            case "11" -> getZuluUrlForVersion("11.76.21", "11.0.25", osType, archType);
            case "17" -> getZuluUrlForVersion("17.54.21", "17.0.13", osType, archType);
            case "21" -> getZuluUrlForVersion("21.38.21", "21.0.5", osType, archType);
            default -> {
                log.warn("不支持的Zulu Java版本: {}", version);
                yield getAdoptiumUrl(version, os, arch);
            }
        };
    }

    /**
     * 构建Zulu下载URL
     */
    private static String getZuluUrlForVersion(String zuluVersion, String jdkVersion, String os, String arch) {
        String extension = os.equals("win") ? "zip" : "tar.gz";
        return String.format(
                "https://cdn.azul.com/zulu/bin/zulu%s-ca-jdk%s-%s_%s.%s",
                zuluVersion, jdkVersion, os, arch, extension
        );
    }

    /**
     * 获取Amazon Corretto下载URL
     */
    private static String getCorrettoUrl(String version, String os, String arch) {
        String osType = normalizeOsForCorretto(os);
        String archType = normalizeArchForCorretto(arch);
        if (osType == null || archType == null) return null;

        String extension = osType.equals("windows") ? "zip" : "tar.gz";

        if (!isVersionSupported(version, "8", "11", "17", "21")) {
            log.warn("不支持的Corretto版本: {}", version);
            return null;
        }

        return String.format(
                "https://corretto.aws/downloads/latest/amazon-corretto-%s-%s-%s-jdk.%s",
                version, archType, osType, extension
        );
    }

    /**
     * 获取Microsoft OpenJDK下载URL
     */
    private static String getMicrosoftUrl(String version, String os, String arch) {
        String osType = normalizeOsForMicrosoft(os);
        String archType = normalizeArchForMicrosoft(arch);
        if (osType == null || archType == null) return null;

        if (!isVersionSupported(version, "11", "17", "21")) {
            log.warn("Microsoft OpenJDK不支持Java版本: {}", version);
            return null;
        }

        String extension = osType.equals("windows") ? "zip" : "tar.gz";

        return String.format(
                "https://aka.ms/download-jdk/microsoft-jdk-%s-%s-%s.%s",
                version, osType, archType, extension
        );
    }

    /**
     * 获取Oracle GraalVM下载URL
     */
    private static String getGraalVMUrl(String version, String os, String arch) {
        String osType = normalizeOsForGraalVM(os);
        String archType = normalizeArchForGraalVM(arch);
        if (osType == null || archType == null) return null;

        String graalVersion;
        switch (version) {
            case "17" -> graalVersion = "17.0.9";
            case "21" -> graalVersion = "21.0.1";
            default -> {
                log.warn("GraalVM不支持Java版本: {}", version);
                return null;
            }
        }

        String extension = osType.equals("windows") ? "zip" : "tar.gz";

        return String.format(
                "https://github.com/graalvm/graalvm-ce-builds/releases/download/jdk-%s/graalvm-community-jdk-%s_%s-%s_bin.%s",
                graalVersion, graalVersion, osType, archType, extension
        );
    }

    // ==================== 操作系统标准化方法 ====================

    private static String normalizeOsForAdoptium(String os) {
        if (os.contains("win")) return "windows";
        if (os.contains("linux")) return "linux";
        if (os.contains("mac")) return "mac";
        return null;
    }

    private static String normalizeOsForZulu(String os) {
        if (os.contains("win")) return "win";
        if (os.contains("linux")) return "linux";
        if (os.contains("mac")) return "macosx";
        return null;
    }

    private static String normalizeOsForCorretto(String os) {
        if (os.contains("win")) return "windows";
        if (os.contains("linux")) return "linux";
        if (os.contains("mac")) return "macos";
        return null;
    }

    private static String normalizeOsForMicrosoft(String os) {
        if (os.contains("win")) return "windows";
        if (os.contains("linux")) return "linux";
        if (os.contains("mac")) return "macOS";
        return null;
    }

    private static String normalizeOsForGraalVM(String os) {
        if (os.contains("win")) return "windows";
        if (os.contains("linux")) return "linux";
        if (os.contains("mac")) return "macos";
        return null;
    }

    // ==================== 架构标准化方法 ====================

    private static String normalizeArchForZulu(String arch) {
        if ("x64".equals(arch) || "amd64".equals(arch)) return "x64";
        if ("aarch64".equals(arch) || "arm64".equals(arch)) return "aarch64";
        if ("x86".equals(arch)) return "i686";
        return "x64"; // 默认
    }

    private static String normalizeArchForCorretto(String arch) {
        if ("x64".equals(arch) || "amd64".equals(arch)) return "x64";
        if ("aarch64".equals(arch) || "arm64".equals(arch)) return "aarch64";
        return "x64"; // 默认
    }

    private static String normalizeArchForMicrosoft(String arch) {
        if ("x64".equals(arch) || "amd64".equals(arch)) return "x64";
        if ("aarch64".equals(arch) || "arm64".equals(arch)) return "aarch64";
        return "x64"; // 默认
    }

    private static String normalizeArchForGraalVM(String arch) {
        if ("x64".equals(arch) || "amd64".equals(arch)) return "x64";
        if ("aarch64".equals(arch) || "arm64".equals(arch)) return "aarch64";
        return "x64"; // 默认
    }

    // ==================== 辅助方法 ====================

    /**
     * 检查版本是否在支持列表中
     */
    private static boolean isVersionSupported(String version, String... supportedVersions) {
        for (String supported : supportedVersions) {
            if (supported.equals(version)) {
                return true;
            }
        }
        return false;
    }
}
