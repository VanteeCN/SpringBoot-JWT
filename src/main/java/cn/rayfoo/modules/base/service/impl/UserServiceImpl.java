package cn.rayfoo.modules.base.service.impl;

import cn.rayfoo.modules.base.entity.User;
import cn.rayfoo.modules.base.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/11 14:12
 */
@Service
@Slf4j
public class UserServiceImpl extends BaseService implements UserService {

    @Override
    public User login(User user) throws Exception {
        //这里假设user、user内的username、password数据都是正确的
        User example = User.builder().username(user.getUsername()).password(user.getPassword()).build();
        //查询用户是否存在
        List<User> reslut = userMapper.select(example);
        //如果没找到代表用户名或者密码错误
        if (ObjectUtils.isEmpty(reslut)) {
            throw new Exception("用户名或密码错误！");
        }
        return reslut.get(0);
    }

    @Override
    public List<User> userList() {
        return userMapper.selectAll();
    }
}
