package cc.endmc.endlessnode.service.impl;

import cc.endmc.endlessnode.domain.Webhooks;
import cc.endmc.endlessnode.mapper.WebhooksMapper;
import cc.endmc.endlessnode.service.WebhooksService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

@Service
public class WebhooksServiceImpl extends ServiceImpl<WebhooksMapper, Webhooks>
        implements WebhooksService {
}
