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
    public Result<String> login(@RequestBody User user) throws Exception {

        //初始化返回值
        Result<String> result = new Result<>();

        //用户登录校验
        User loginUser = userService.login(user);

        //没有抛出异常表示正常
        result.setCode(HttpStatus.OK.value());
        result.setMsg("认证成功！");

        //声明payload
        Map<String, String> payload = new HashMap<>(2);

        //初始化payload
        payload.put("id", loginUser.getId().toString());
        payload.put("username", loginUser.getUsername());

        //获取令牌
        String token = JWTUtil.getToken(payload, 20);

        //在响应结果中添加token
        result.setData(token);

        //返回结果
        return result;
    }

    @GetMapping("/list")
    public Result<List<User>> userList() throws Exception {

        //初始化返回值
        Result<List<User>> result = new Result<>();
        //如果成功，设置状态码和查询到的结果
        result.setCode(HttpStatus.OK.value());
        result.setMsg("查询成功！");
        List<User> users = userService.userList();
        result.setData(users);
        //返回结果
        return result;
    }

}
