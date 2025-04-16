package cc.endmc.endlessnode.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

@Slf4j
@Service
public class FileDownloadService {

    @Async
    public void downloadFileAsync(String url, String path, String fileName) {
        try {
            // 配置SSL上下文
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

            // 打开连接
            URLConnection connection = new URL(url).openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(30000);

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

            // 创建输入流并下载文件
            try (InputStream in = connection.getInputStream()) {
                Files.copy(in, targetPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                log.info("File downloaded successfully: {}", targetPath);
            }
        } catch (Exception e) {
            log.error("Error downloading file from {} to {}: {}", url, path, e.getMessage());
        }
    }

    /**
     * 从URL或HTTP响应头中获取文件名
     */
    public String getFileNameFromUrl(String url, URLConnection connection) {
        // 首先尝试从Content-Disposition头获取文件名
        String disposition = connection.getHeaderField("Content-Disposition");
        if (disposition != null) {
            int index = disposition.indexOf("filename=");
            if (index != -1) {
                String fileName = disposition.substring(index + 10);
                if (fileName.startsWith("\"") && fileName.endsWith("\"")) {
                    fileName = fileName.substring(1, fileName.length() - 1);
                }
                return fileName;
            }
        }

        // 从URL中获取文件名
        try {
            String path = new URL(url).getPath();
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash != -1) {
                String fileName = path.substring(lastSlash + 1);
                // URL解码文件名
                fileName = java.net.URLDecoder.decode(fileName, "UTF-8");
                return fileName;
            }
        } catch (Exception e) {
            // 忽略URL解析错误
        }

        // 如果无法获取文件名，生成一个基于时间戳的默认文件名
        return "downloaded_file_" + System.currentTimeMillis();
    }
} 