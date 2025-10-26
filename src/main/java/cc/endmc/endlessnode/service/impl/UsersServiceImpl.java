package cc.endmc.endlessnode.service.impl;

import cc.endmc.endlessnode.domain.Users;
import cc.endmc.endlessnode.mapper.UsersMapper;
import cc.endmc.endlessnode.service.UsersService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * @author Memory
 * @description 针对表【users】的数据库操作Service实现
 * @createDate 2025-01-27 10:00:00
 */
@Service
public class UsersServiceImpl extends ServiceImpl<UsersMapper, Users>
        implements UsersService {

}
