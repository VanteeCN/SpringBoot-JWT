package cn.rayfoo.modules.base.interceptor;

import cn.rayfoo.common.util.JWTUtil;
import org.springframework.web.servlet.HandlerInterceptor;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/11 15:58
 */
public class JWTInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        //从请求头内获取token
        String token = request.getHeader("authorization");

        //验证令牌  如果令牌不正确会出现异常 被全局异常处理
        JWTUtil.verify(token);

        return true;
    }

}
