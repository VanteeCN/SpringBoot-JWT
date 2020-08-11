package cn.rayfoo.modules.base.service;

import cn.rayfoo.modules.base.entity.User;

import java.util.List;
import java.util.Map;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/11 14:11
 */
public interface UserService {

    /**
     * 用户登录方法
     * @param user 用户
     */
    User login(User user) throws Exception;

    /**
     * 查询所有用户信息
     * @return
     */
    List<User> userList();
}
