package cc.endmc.endlessnode.service;

import cc.endmc.endlessnode.domain.Webhooks;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Webhook 事件通知：关键事件发生时 POST 到配置的 URL。
 */
@Slf4j
@Service
public class WebhookService {

    private final WebhooksService webhooksService;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public WebhookService(WebhooksService webhooksService) {
        this.webhooksService = webhooksService;
    }

    /**
     * 触发事件通知
     *
     * @param event   事件名称（如 server.start, server.crash, backup.complete）
     * @param payload JSON 格式的消息体
     */
    public void fireEvent(String event, String payload) {
        List<Webhooks> all = webhooksService.lambdaQuery().eq(Webhooks::getEnabled, 1).list();
        for (Webhooks wh : all) {
            if (wh.getEvents() == null) continue;
            Set<String> events = Set.of(wh.getEvents().split(","));
            if (!events.contains(event) && !events.contains("*")) continue;
            sendAsync(wh.getUrl(), event, payload);
        }
    }

    private void sendAsync(String url, String event, String payload) {
        try {
            String body = "{\"event\":\"" + event + "\",\"data\":" + payload + "}";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                    .thenAccept(resp -> log.debug("Webhook {} 响应: {}", event, resp.statusCode()))
                    .exceptionally(e -> {
                        log.warn("Webhook {} 发送失败: {}", event, e.getMessage());
                        return null;
                    });
        } catch (Exception e) {
            log.warn("Webhook {} 构建请求失败: {}", event, e.getMessage());
        }
    }
}
