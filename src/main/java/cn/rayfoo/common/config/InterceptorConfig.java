package cn.rayfoo.common.config;

import cn.rayfoo.modules.base.interceptor.JWTInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.lang.reflect.Array;
import java.util.Arrays;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/11 16:13
 */
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {



    @Override
    public void addInterceptors(InterceptorRegistry registry) {

        registry.addInterceptor(new JWTInterceptor())
                .addPathPatterns("/**")
                .excludePathPatterns(Arrays.asList("/","/index.html","/css/**","/js/**"))
                .excludePathPatterns("/user/login");

    }

}
