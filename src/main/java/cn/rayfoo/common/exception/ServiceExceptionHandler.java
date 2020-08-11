package cn.rayfoo.common.exception;

import cn.rayfoo.common.response.Result;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;


/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p>全局异常处理</p>
 * @date 2020/8/11 16:36
 */
@RestControllerAdvice
@Slf4j
public class ServiceExceptionHandler {

    /**
     * 默认异常的状态码
     */
    private static final Integer DEFAULT_EXCEPTION = 500;

    /**
     * token超时异常状态码
     */
    private static final Integer TOKEN_ERROR_EXCEPTION = 505;

    /**
     * token无效状态码
     */
    private static final Integer TOKEN_EXPIRED_EXCEPTION = 506;


    /**
     * 处理token异常
     */
    @ExceptionHandler({SignatureVerificationException.class, AlgorithmMismatchException.class, JWTDecodeException.class})
    public Result<String> tokenErrorException() {
        Result<String> result = new Result<>();
        result.setCode(TOKEN_ERROR_EXCEPTION);
        result.setMsg("无效的token！");
        log.error("无效的token");
        return result;
    }

    /**
     * 处理token异常
     */
    @ExceptionHandler({TokenExpiredException.class})
    public Result<String> tokenExpiredException() {
        Result<String> result = new Result<>();
        result.setCode(TOKEN_EXPIRED_EXCEPTION);
        result.setMsg("token超时！");
        log.error("用户token超时");
        return result;
    }

    /**
     * 处理所有RuntimeException异常
     */
    @ExceptionHandler({RuntimeException.class})
    public Result<String> allException(RuntimeException e) {
        Result<String> result = new Result<>();
        result.setCode(DEFAULT_EXCEPTION);
        result.setMsg( e.getMessage());
        log.error(e.getMessage());
        e.printStackTrace();
        return result;
    }

    /**
     * 处理所有Exception异常
     */
    @ExceptionHandler({Exception.class})
    public Result<String> allException(Exception e) {
        Result<String> result = new Result<>();
        result.setCode(DEFAULT_EXCEPTION);
        result.setMsg( e.getMessage());
        log.error(e.getMessage());
        e.printStackTrace();
        return result;
    }

}
