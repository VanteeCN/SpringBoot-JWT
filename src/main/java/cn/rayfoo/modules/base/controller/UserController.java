package cn.rayfoo.modules.base.controller;

import cn.rayfoo.common.response.HttpStatus;
import cn.rayfoo.common.response.Result;
import cn.rayfoo.common.util.JWTUtil;
import cn.rayfoo.modules.base.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/11 14:12
 */
@RestController
@Slf4j
@RequestMapping("/user")
public class UserController extends BaseController {


    @PostMapping("/login")
    public Result login(@RequestBody User user) throws Exception {



        //用户登录校验
        User loginUser = userService.login(user);


        //声明payload
        Map<String, String> payload = new HashMap<>(2);

        //初始化payload
        payload.put("id", loginUser.getId().toString());
        payload.put("username", loginUser.getUsername());

        //获取令牌
        String token = JWTUtil.getToken(payload, 20);

        //初始化返回值
        Result result = Result.builder()
                .code(HttpStatus.OK.value())
                .msg("认证成功！")
                .data(token)
                .build();

        //返回结果
        return result;
    }

    @GetMapping("/list")
    public Result userList() throws Exception {
        //查询所有用户西信息
        List<User> users = userService.userList();
        //初始化返回值  如果成功，设置状态码和查询到的结果
        Result result = Result.builder()
                .code(HttpStatus.OK.value())
                .msg("查询成功！")
                .data(users)
                .build();
        //返回结果
        return result;
    }

}
