package cc.endmc.endlessnode.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
public class FileDownloadService {

    private static final int CONNECT_TIMEOUT = 10000; // 10秒
    private static final int READ_TIMEOUT = 60000; // 60秒
    private static final int MAX_REDIRECTS = 5; // 最大重定向次数

    @Async
    public void downloadFileAsync(String url, String path) {
        HttpURLConnection connection = null;
        try {
            log.info("Starting download from URL: {} to path: {}", url, path);

            // 打开连接并处理重定向
            connection = openConnectionWithRedirects(url);

            // 从响应头获取文件名
            String fileName = extractFileNameFromHeaders(connection, url);
            log.info("Detected file name: {}", fileName);

            // 构建目标路径
            Path targetPath = Paths.get(path);

            // 如果目标是目录，则添加文件名
            if (Files.isDirectory(targetPath) || !targetPath.toString().contains(".")) {
                targetPath = targetPath.resolve(fileName);
            }

            // 创建父目录（如果不存在）
            Path parent = targetPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            // 获取文件大小
            long contentLength = connection.getContentLengthLong();
            if (contentLength > 0) {
                log.info("File size: {} bytes", contentLength);
            }

            // 下载文件
            try (InputStream in = connection.getInputStream()) {
                long bytesWritten = Files.copy(in, targetPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                log.info("File downloaded successfully: {} ({} bytes)", targetPath, bytesWritten);
            }
        } catch (Exception e) {
            log.error("Error downloading file from {} to {}: {}", url, path, e.getMessage(), e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * 创建仅用于当前下载连接的 SSLContext（信任所有证书）。
     * 不修改 JVM 全局默认值，避免影响其他 HTTPS 连接。
     */
    private SSLContext createTrustAllSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        return sslContext;
    }

    /**
     * 打开连接并处理重定向
     */
    private HttpURLConnection openConnectionWithRedirects(String urlString) throws Exception {
        int redirectCount = 0;
        String currentUrl = urlString;
        SSLContext trustAllContext = null;

        while (redirectCount < MAX_REDIRECTS) {
            URL url = new URL(currentUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // 仅对 HTTPS 连接应用局部 SSL 配置，不修改 JVM 全局默认值
            if (connection instanceof HttpsURLConnection httpsConn) {
                if (trustAllContext == null) {
                    trustAllContext = createTrustAllSSLContext();
                }
                httpsConn.setSSLSocketFactory(trustAllContext.getSocketFactory());
                httpsConn.setHostnameVerifier((hostname, session) -> true);
            }

            // 设置请求属性
            connection.setConnectTimeout(CONNECT_TIMEOUT);
            connection.setReadTimeout(READ_TIMEOUT);
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            connection.setRequestProperty("Accept", "*/*");
            connection.setRequestProperty("Accept-Encoding", "identity");
            connection.setInstanceFollowRedirects(false); // 手动处理重定向

            int responseCode = connection.getResponseCode();
            log.debug("Response code: {} for URL: {}", responseCode, currentUrl);

            // 检查是否需要重定向
            if (responseCode == HttpURLConnection.HTTP_MOVED_PERM ||
                    responseCode == HttpURLConnection.HTTP_MOVED_TEMP ||
                    responseCode == HttpURLConnection.HTTP_SEE_OTHER ||
                    responseCode == 307 || responseCode == 308) {

                String newUrl = connection.getHeaderField("Location");
                if (newUrl == null || newUrl.isEmpty()) {
                    throw new Exception("Redirect location is empty");
                }

                // 处理相对URL
                if (!newUrl.startsWith("http")) {
                    URL base = new URL(currentUrl);
                    newUrl = new URL(base, newUrl).toString();
                }

                log.info("Redirecting to: {}", newUrl);
                connection.disconnect();
                currentUrl = newUrl;
                redirectCount++;
            } else if (responseCode == HttpURLConnection.HTTP_OK) {
                return connection;
            } else {
                connection.disconnect();
                throw new Exception("HTTP error code: " + responseCode);
            }
        }

        throw new Exception("Too many redirects (max: " + MAX_REDIRECTS + ")");
    }

    /**
     * 从HTTP响应头中提取文件名
     */
    private String extractFileNameFromHeaders(HttpURLConnection connection, String url) {
        // 1. 尝试从Content-Disposition头获取
        String disposition = connection.getHeaderField("Content-Disposition");
        if (disposition != null && !disposition.isEmpty()) {
            String fileName = parseContentDisposition(disposition);
            if (fileName != null && !fileName.isEmpty()) {
                return sanitizeFileName(fileName);
            }
        }

        // 2. 从URL路径获取
        String fileName = extractFileNameFromUrl(url);
        if (fileName != null && !fileName.isEmpty()) {
            return sanitizeFileName(fileName);
        }

        // 3. 根据Content-Type生成文件名
        String contentType = connection.getContentType();
        String extension = getExtensionFromContentType(contentType);
        return "download_" + System.currentTimeMillis() + extension;
    }

    /**
     * 解析Content-Disposition头
     */
    private String parseContentDisposition(String disposition) {
        // 支持多种格式：
        // filename="example.txt"
        // filename=example.txt
        // filename*=UTF-8''example.txt
        // attachment; filename="example.txt"

        // 优先处理 filename*（RFC 5987）
        Pattern filenameStarPattern = Pattern.compile("filename\\*=([^']+)'([^']*)'(.+)");
        Matcher matcher = filenameStarPattern.matcher(disposition);
        if (matcher.find()) {
            String encoding = matcher.group(1);
            String fileName = matcher.group(3);
            try {
                return URLDecoder.decode(fileName, encoding);
            } catch (Exception e) {
                log.warn("Failed to decode filename with encoding {}: {}", encoding, e.getMessage());
            }
        }

        // 处理标准 filename
        Pattern filenamePattern = Pattern.compile("filename\\s*=\\s*[\"']?([^\"';]+)[\"']?");
        matcher = filenamePattern.matcher(disposition);
        if (matcher.find()) {
            String fileName = matcher.group(1).trim();
            try {
                // 尝试URL解码
                return URLDecoder.decode(fileName, StandardCharsets.UTF_8.name());
            } catch (Exception e) {
                return fileName;
            }
        }

        return null;
    }

    /**
     * 从URL中提取文件名
     */
    public String extractFileNameFromUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            String path = url.getPath();

            // 移除查询参数
            int queryIndex = path.indexOf('?');
            if (queryIndex != -1) {
                path = path.substring(0, queryIndex);
            }

            // 获取最后一个路径段
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash != -1 && lastSlash < path.length() - 1) {
                String fileName = path.substring(lastSlash + 1);
                // URL解码
                fileName = URLDecoder.decode(fileName, StandardCharsets.UTF_8.name());
                if (!fileName.isEmpty()) {
                    return fileName;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract filename from URL: {}", e.getMessage());
        }

        return "download_" + System.currentTimeMillis();
    }

    /**
     * 根据Content-Type获取文件扩展名
     */
    private String getExtensionFromContentType(String contentType) {
        if (contentType == null || contentType.isEmpty()) {
            return "";
        }

        // 移除参数（如 charset）
        int semicolon = contentType.indexOf(';');
        if (semicolon != -1) {
            contentType = contentType.substring(0, semicolon);
        }
        contentType = contentType.trim().toLowerCase();

        // 常见MIME类型映射
        switch (contentType) {
            case "application/zip":
                return ".zip";
            case "application/x-zip-compressed":
                return ".zip";
            case "application/java-archive":
                return ".jar";
            case "application/pdf":
                return ".pdf";
            case "application/json":
                return ".json";
            case "application/xml":
            case "text/xml":
                return ".xml";
            case "text/plain":
                return ".txt";
            case "text/html":
                return ".html";
            case "image/jpeg":
                return ".jpg";
            case "image/png":
                return ".png";
            case "image/gif":
                return ".gif";
            case "application/octet-stream":
            default:
                return "";
        }
    }

    /**
     * 校验 URL 是否安全（非 SSRF 目标）。
     * 解析主机名对应的 IP 地址，拒绝私有/环路/链路本地等内网地址。
     *
     * @param url 待校验的 URL 字符串
     * @throws IllegalArgumentException 如果 URL 不安全或无法解析
     */
    public void validateUrlSafety(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL不能为空");
        }

        String lower = url.toLowerCase().trim();
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
            throw new IllegalArgumentException("仅支持HTTP和HTTPS协议");
        }

        URL parsed;
        try {
            parsed = new URL(url);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL格式不正确: " + e.getMessage());
        }

        String host = parsed.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("URL缺少主机名");
        }

        // 解析主机名到 IP 地址（防止 DNS rebinding 也在此处覆盖）
        InetAddress address;
        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("无法解析主机名: " + host);
        }

        if (address.isLoopbackAddress()) {
            throw new IllegalArgumentException("不允许访问本机地址");
        }
        if (address.isSiteLocalAddress()) {
            throw new IllegalArgumentException("不允许访问内网地址");
        }
        if (address.isLinkLocalAddress()) {
            throw new IllegalArgumentException("不允许访问链路本地地址");
        }
        if (address.isAnyLocalAddress()) {
            throw new IllegalArgumentException("不允许访问通配地址");
        }
        if (address.isMulticastAddress()) {
            throw new IllegalArgumentException("不允许访问组播地址");
        }

        // 显式阻断云元数据服务地址 (169.254.169.254)
        String hostAddress = address.getHostAddress();
        if (hostAddress != null && hostAddress.startsWith("169.254.")) {
            throw new IllegalArgumentException("不允许访问链路本地地址");
        }
    }

    /**
     * 清理文件名，移除非法字符
     */
    private String sanitizeFileName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return "download_" + System.currentTimeMillis();
        }

        // 移除路径分隔符和其他非法字符
        fileName = fileName.replaceAll("[\\\\/:*?\"<>|]", "_");

        // 移除前后空格
        fileName = fileName.trim();

        // 如果文件名为空或只包含点，生成默认名称
        if (fileName.isEmpty() || fileName.matches("^\\.+$")) {
            return "download_" + System.currentTimeMillis();
        }

        return fileName;
    }
} 