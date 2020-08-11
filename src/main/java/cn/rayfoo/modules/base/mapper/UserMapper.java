package cn.rayfoo.modules.base.mapper;

import cn.rayfoo.modules.base.entity.User;
import org.springframework.stereotype.Repository;
import tk.mybatis.mapper.common.Mapper;
import tk.mybatis.mapper.common.MySqlMapper;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/11 14:09
 */
@Repository
public interface UserMapper extends Mapper<User>, MySqlMapper<User> {
}
