package cn.rayfoo.modules.base.service.impl;

import cn.rayfoo.modules.base.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/11 14:12
 */
public class BaseService {

    @Autowired
    protected UserMapper userMapper;

}
