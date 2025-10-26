package cc.endmc.endlessnode.mapper;

import cc.endmc.endlessnode.domain.Users;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * @author Memory
 * @description 针对表【users】的数据库操作Mapper
 * @createDate 2025-01-27 10:00:00
 */
@Mapper
public interface UsersMapper extends BaseMapper<Users> {

}
