package cn.rayfoo.modules.base.controller;

import cn.rayfoo.modules.base.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ModelAttribute;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * @date 2020/8/5 14:34
 * @description 基础controller
 */
public class BaseController {

    /**
     * 注入全部service
     */
    @Autowired
    protected UserService userService;


    /**
     * 创建session、Request、Response等对象
     */
    protected HttpServletRequest request;
    protected HttpServletResponse response;
    protected HttpSession session;


    /**
     * 在每个子类方法调用之前先调用
     * 设置request,response,session这三个对象
     *
     * @param request
     * @param response
     */
    @ModelAttribute
    public void setReqAndRes(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
        this.session = request.getSession(true);
        //可以在此处拿到当前登录的用户
    }

}
