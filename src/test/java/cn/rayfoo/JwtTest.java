package cn.rayfoo;

import cn.rayfoo.common.util.JWTUtil;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.*;


/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/10 16:18
 */
public class JwtTest {

    public static void main(String[] args) throws Exception {

        //创建map
        Map<String, String> map = new HashMap<>();
        map.put("username", "rayfoo");
        //颁发token
        String token = JWTUtil.getToken(map);
        System.out.println(token);


        //解析token
        DecodedJWT verify = JWTUtil.verify(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.VzZXJuYW1lIjoicmF5Zm9vIn0eyJleHAiOjE1OTcxMzE0NDUsIn.nosHV3AipoS94e8mPmGT-4js8hB232vAJygSG8IoSUA"
        );
        System.out.println(verify.getClaim("username").asString());

    }

}
