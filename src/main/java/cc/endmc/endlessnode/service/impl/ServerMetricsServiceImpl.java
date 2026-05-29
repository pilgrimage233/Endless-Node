package cc.endmc.endlessnode.service.impl;

import cc.endmc.endlessnode.domain.ServerMetrics;
import cc.endmc.endlessnode.mapper.ServerMetricsMapper;
import cc.endmc.endlessnode.service.ServerMetricsService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

@Service
public class ServerMetricsServiceImpl extends ServiceImpl<ServerMetricsMapper, ServerMetrics>
        implements ServerMetricsService {
}
