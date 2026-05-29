package cc.endmc.endlessnode.service.impl;

import cc.endmc.endlessnode.domain.ScheduledTasks;
import cc.endmc.endlessnode.mapper.ScheduledTasksMapper;
import cc.endmc.endlessnode.service.ScheduledTasksService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

@Service
public class ScheduledTasksServiceImpl extends ServiceImpl<ScheduledTasksMapper, ScheduledTasks>
        implements ScheduledTasksService {
}
