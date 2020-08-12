package cn.rayfoo.common.response;

import lombok.Builder;
import lombok.Data;


/**
 * @author rayfoo@qq.com
 * @date 2020年8月6日
 */
@Data@Builder
public class Result {

    /**
     * 状态码
     */
    private Integer code;

    /**
     * 提示信息
     */
    private String  msg;

    /**
     * 数据记录
     */
    private Object data;

    public Result() {
    }

    public Result(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public Result(Integer code, String msg, Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

}
