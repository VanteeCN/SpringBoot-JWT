# SpringBoot实现JWT认证



本文会从Token、JWT、JWT的实现、JWTUtil封装到SpringBoot中使用JWT，如果有一定的基础，可以跳过前面的内容~

## Token



### 简介

Token 是一个临时、唯一、保证不重复的令牌，例如智能门锁，它可以生成一个临时密码，具有一定时间内的有效期。



### 实现思路

UUID具有上述的特性，所以我们可以使用UUID作为token，生产UUID后放入Redis，设置Redis的过期时间。



### Token的SessionID

token和SESSIONID非常的相似，但是SESSIONID在分布式项目中不能共享，虽然SESSION可以通过Redis等技术实现共享，但是使用这类技术会降低项目的性能和可用性。所以现在普通使用Token代替Session使用。



### 简单的Token实现思路



#### 实现思路：

1. 验证用户的账号密码
2. 如果正确，生成UUID作为Key
3. 将此Key作为Key，将用户信息作为Value，存入Redis
4. 最后返回Token给客户端，客户端将Cookie保存到Cookie中



用户在每次请求时，都会携带此Token，后端在拦截器中校验Token是否存在，如果存在找到对应的用户信息，判断其有哪些权限。



#### Token优点：

1. 可以通过Header、Body提交，实现跨域操作
2. 可以隐藏参数的真实性，实现参数的脱敏
3. 临时、唯一



#### 存在问题：

1. 使用Token，必须依赖Redis和Cookie
2. 需要频繁操作Redis



## JWT

### 简介

JWT，全称Json Web Token，是目前最流行的跨域认证解决方案。它的实现思想和上面的token是基本一致的，是一种更加成熟和完善的解决方案。



### 原理

JWT的原理就是，当服务器认证账号密码通过后，生成一个JSON对象，返回给用户，保存在Cookie中。当用户下一次访问的时候自动携带这个JSON对象，服务器可以根据这个对象判断用户的身份。为了防止用户篡改数据信息，服务器生成这个JSON的时候，会进行一些加密操作。此时服务器中就不需要保存session数据。



### JWT的数据结构

JWT中的数据分为三部分，每部分都是一串很长的字符串，中间用`.`间隔

- header： 头部，标记加密算法
- Payload： 负载，存放具体数据
- Signature：签名，Payload采用MD5加密后的签名值

完整的格式为：header.Payload.Signature



### Header

Header部分是由一个JSON对象组成，它描述JWT的元数据，通常是下面的样子：

```json
{

	'alg' : "HS256",
	"typ" : "JWT"

}
```

alg表示签名的算法，默认为HMAC SHA256（可以写成 HS256）

typ属性表示令牌的类型，JWT令牌统一写为JWT

生成JWT后，此部分会进行BASE64编码，最终被解析为：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

jwt中的Header部分的内容默认是没有加密的，只是进行了Base64处理。可以直接使用Base64反加密获取原文。

### Payload

Payload部分也是一个JSON对象，用来存放实际需要传递的数据。JWT规定了7个官方字段：



- iss (issuer)：签发人
- exp (expiration time)：过期时间
- sub (subject)：主题
- aud (audience)：受众
- nbf (Not Before)：生效时间
- iat (Issued At)：签发时间
- jti (JWT ID)：编号



除了官方字段，还可以支持自定义字段，下面就是一个例子：

```JSON
{
  "name": "rayfoo",
  "phone": 18338862369
}
```

生产JWT后的：

```
eyJuYW1lIjoicmF5Zm9vIiwicGhvbmUiOjE4MzM4ODYyMzY5fQ
```

注意，这部分的内容默认也是没有加密的，只是进行了Base64编码。可以直接使用Base64反加密获取原文。但是我们可以对其进行一些混淆操作。



### Signature

Signature 部分是对前两部分的签名，防止数据篡改。

首先，需要指定一个密钥（secret）。这个密钥只有服务器才知道，不能泄露给用户。然后，使用 Header 里面指定的签名算法（默认是 HMAC SHA256），按照下面的公式产生签名。

这一段并不是使用base64加密，而是使用header中提供的加密方式进行的加密.

可以浅显的理解为将Payload中的数据按照header，payload+密钥（secret）作为一个整体进行MD5（也可能是任意类型的）加密。在下面这段代码中，密钥就是：rayfoo。

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  rayfoo
)
```



jwt生成的signature

```
AIwKf4x_nYr1N_cmw_VQ5t_nuaX5b-gTN8RgHtkTO4w
```



### 完整的token

算出签名以后，把 Header、Payload、Signature 三个部分拼成一个字符串，每个部分之间用"点"（`.`）分隔，就可以返回给用户。这就是完整的JWT：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoicmF5Zm9vIiwicGhvbmUiOjE4MzM4ODYyMzY5fQ.AIwKf4x_nYr1N_cmw_VQ5t_nuaX5b-gTN8RgHtkTO4w
```



可以在https://jwt.io/#encoded-jwt进行测试 

###  Base64URL编码

前面提到，Header 和 Payload 串型化的算法是 Base64URL。这个算法跟 Base64 算法基本类似，但有一些小的不同。

JWT 作为一个令牌（token），有些场合可能会放到 URL（比如 api.example.com/?token=xxx）。Base64 有三个字符`+`、`/`和`=`，在 URL 里面有特殊含义，所以要被替换掉：`=`被省略、`+`替换成`-`，`/`替换成`_` 。这就是 Base64URL 算法。



### JWT的使用方式



客户端收到服务器返回的 JWT，可以储存在 Cookie 里面，也可以储存在 localStorage。

此后，客户端每次与服务器通信，都要带上这个 JWT。你可以把它放在 Cookie 里面自动发送，但是这样不能跨域，所以更好的做法是放在 HTTP 请求的头信息`Authorization`字段里面。

 ```javascript
 Authorization: Bearer <token>
 ```

另一种做法是，跨域的时候，JWT 就放在 POST 请求的数据体里面。



### JWT 的几个特点



#### 优点:

（1）JWT 默认是不加密，但也是可以加密的。生成原始 Token 以后，可以用密钥再加密一次，不容易被客户端修改。

（2）JWT 不加密的情况下，不能将秘密数据写入 JWT。

（3）JWT 不仅可以用于认证，也可以用于交换信息。有效使用 JWT，可以降低服务器查询数据库的次数。效率也比token高。



#### 缺点：

（1）JWT 的最大缺点是，由于服务器不保存 session 状态，因此无法在使用过程中废止某个 token，或者更改 token 的权限。也就是说，一旦 JWT 签发了，在到期之前就会始终有效，除非服务器部署额外的逻辑。

（2）JWT 本身包含了认证信息，一旦泄露，任何人都可以获得该令牌的所有权限。为了减少盗用，JWT 的有效期应该设置得比较短。对于一些比较重要的权限，使用时应该再次对用户进行认证。

（3）为了减少盗用，JWT 不应该使用 HTTP 协议明码传输，要使用 HTTPS 协议传输。

（4）如果jwt中payload的数据过多，会占用服务器的带宽资源。



## 如何手写一个JWT

了解了上面的一些概念后，我们可以自己动手实现一个jwt

1. 创建两个JSONObject对象，分别作为Header和Payload
2. 初始化Header，添加相应内容，进行base64编码
3. 初始化Payload，添加相应内容，进行base64编码+混淆
4. 对Payload进行md5加盐、加密

对三部分内容进行拼接，使用`.`间隔



建议在payload中增加一个时间戳，用于指定过期时间。



## 在Java中使用JWT

jwt提供了不止一种的实现

- Auth0实现 的 java-jwt

- Brian Campbell实现的 jose4j

- connect2id实现的 nimbus-jose-jwt

- Les Haziewood实现的 jjwt
- Inversoft实现的prime-jwt
- Vertx实现的vertx-auth-jwt.

几乎所有库都要求JAVA版本1.7或更高版本, 1.6或以下的版本需要二次开发(或不支持)

从易用性, 扩展性, 完整性等来看, 使用首先推荐 jose4j, 其次是 Nimbus-jose-jwt.

关于这些类库的评测：http://andaily.com/blog/?p=956



### 封装JWT工具类&payload加密



#### 引入依赖



下面的代码都是基于auth0 提供的 java-jwt实现的

```xml
        <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>3.4.0</version>
        </dependency>
```



#### 封装工具类

由于JWT中的payload是不安全的，没有进行加密，所以在工具类中进行了加密操作。

这里的加密操作只是一种加密思路，你也可以使用自己的任意加密方式来让payload中的内容更加安全。

```java
package cn.rayfoo.common.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p>JSON WEB TOKEN 工具类</p>
 * @date 2020/8/11 9:19
 */
public class JWTUtil {

    /**
     * 签名 此签名为 rayfoo 的16位 大写 MD5
     */
    private static final String SIGN_KEY = "5A1332068BA9FD17";

    /**
     * 默认的过期时间，30分钟
     */
    private static final Integer DEFAULT_EXPIRES = 60 * 30;

    /**
     * token默认的长度
     */
    private static final Integer DEFAULT_TOKEN_SIZE = 3;


    /**
     * 生成令牌
     *
     * @param map     数据正文
     * @param expires 过期时间，单位(秒)
     */
    public static String getToken(Map<String, String> map, Integer expires) throws Exception {

        //创建日历
        Calendar instance = Calendar.getInstance();
        //设置过期时间
        instance.add(Calendar.SECOND, expires);

        //创建jwt builder对象
        JWTCreator.Builder builder = JWT.create();

        //payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });

        //指定过期时间
        String token = builder.withExpiresAt(instance.getTime())
                //设置加密方式
                .sign(Algorithm.HMAC256(SIGN_KEY));
        //返回tokean
        return confoundPayload(token);
    }

    /**
     * 解析token
     *
     * @param token 输入混淆payload后的token
     */
    public static DecodedJWT verify(String token) throws Exception {
        //解析token
        String dToken = deConfoundPayload(token);
        //创建返回结果
        return JWT.require(Algorithm.HMAC256(SIGN_KEY)).build().verify(dToken);

    }

    /**
     * 重载getToken 此方法为获取默认30分钟有效期的token
     *
     * @param map 数据正文
     */
    public static String getToken(Map<String, String> map) throws Exception {
        return getToken(map, DEFAULT_EXPIRES);
    }


    /**
     * 对一个base64编码进行混淆  此处还可以进行replace混淆，考虑到效率问题，这里就不做啦~
     * 对于加密的思路还有位移、字符替换等~
     * @param token 混淆payload前的token
     */
    private static String confoundPayload(String token) throws Exception {
        //分割token
        String[] split = token.split("\\.");
        //如果token不符合规范
        if (split.length != DEFAULT_TOKEN_SIZE) {
            throw new JWTDecodeException("签名不正确");
        }
        //取出payload
        String payload = split[1];
        //获取长度
        int length = payload.length() / 2;
        //指定截取点
        int index = payload.length() % 2 != 0 ? length + 1 : length;
        //混淆处理后的token
        return split[0] + "." + reversePayload(payload, index) + "." + split[2];
    }

    /**
     * 对一个混淆后的base编码进行解析
     *
     * @param token 混淆后的token
     */
    private static String deConfoundPayload(String token) throws Exception {
        //分割token
        String[] split = token.split("\\.");
        //如果token不符合规范
        if (split.length != DEFAULT_TOKEN_SIZE) {
            throw new JWTDecodeException("签名不正确");
        }
        //取出payload
        String payload = split[1];
        //返回解析后的token
        return split[0] + "." + reversePayload(payload, payload.length() / 2) + "." + split[2];
    }

    /**
     * 将md5编码位移
     *
     * @param payload payload编码
     * @param index   位移处
     */
    private static String reversePayload(String payload, Integer index) {
        return payload.substring(index) + payload.substring(0, index);
    }


}

```

此时，我们就可以使用此工具类颁发token、解析token了~

```java
package cn.rayfoo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.apache.commons.codec.binary.StringUtils;

import java.util.*;


/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p></p>
 * @date 2020/8/10 16:18
 */
public class JwtTest {

    //密钥
    private static final String SIGN_KEY = "rayfoo";

    public static void main(String[] args) throws Exception{

        //创建map
        Map<String, String> map = new HashMap<>();
        map.put("username", "rayfoo");
        //颁发token
        String token = JWTUtil.getToken(map);
        System.out.println(token);

        //解析token
        DecodedJWT verify = JWTUtil.verify(token);
        System.out.println(verify.getClaim("username").asString());

    }

}

```



此时，使用混淆后的token解析，发现无法解析到payload：

![](https://rayfoo-dev-tst.oss-cn-beijing.aliyuncs.com/img/20200811135746.png)



### 常见异常的处理

- JWTDecodeException：header、payload被修改会出现的异常
- SignatureVerificationException：签名不匹配异常
- TokenExpiredException：令牌过期异常
- AlgorithmMismatchException：算法不匹配异常

建议使用全局异常处理进行细粒度异常处理



### 在SpringBoot中使用JWT



#### 使用JWT之前

先基于SpringBoot+MyBatis实现一个简单的查询操作，完整的代码稍后会上传到Github，这里只进行关键部分的介绍。

传统的密码校验：

```java
    @Override
    public User login(User user) throws Exception {
        //这里假设user、user内的username、password数据都是正确的
        User example = User.builder().username(user.getUsername()).password(user.getPassword()).build();
        //查询用户是否存在
        List<User> reslut = userMapper.select(example);
        //如果没找到代表用户名或者密码错误
        if (ObjectUtils.isEmpty(reslut)) {
            throw new Exception("用户名或密码错误！");
        }
        return reslut.get(0);
    }
```

上面时service层代码，如果执行没有报错说明拿到了正确的查询结果，此时在Controller中可以将用户的登录信息保存到Session或者Redis中，用于校验。

```java
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody User user) {

        //初始化返回值
        Map<String, Object> map = new HashMap<>(2);
        try {
            //用户登录校验
            User loginUser = userService.login(user);
            //没有抛出异常表示正常
            map.put("code", 200);
            map.put("msg", "认证成功！");
            //使用session或者redis记录。。。
        } catch (Exception exception) {
            //如果出现异常记录错误信息
            map.put("code", 500);
            map.put("msg", exception.getMessage());
        }
        //返回结果
        return map;
    }
```

#### 使用JWT

有了JWT以后，我们可以使用token来代替Session/Redis

```java
 @PostMapping("/login")
    public Map<String, Object> login(@RequestBody User user) {

        //初始化返回值
        Map<String, Object> map = new HashMap<>(3);
        try {
            //用户登录校验
            User loginUser = userService.login(user);

            //没有抛出异常表示正常
            map.put("code", 200);
            map.put("msg", "认证成功！");

            //声明payload
            Map<String, String> payload = new HashMap<>(2);

            //初始化payload
            payload.put("id", loginUser.getId().toString());
            payload.put("username", loginUser.getUsername());

            //获取令牌
            String token = JWTUtil.getToken(payload,20);

            //在响应结果中添加token
            map.put("token", token);


        } catch (Exception exception) {
            //如果出现异常记录错误信息
            map.put("code", 500);
            map.put("msg", exception.getMessage());
        }
        //返回结果
        return map;
    }
```



#### JWT包含有权限的接口

这里的代码没有进行优化，只是用最简单直白的方式介绍了JWT对接口的保护

```java
@GetMapping("/list")
    public Map<String, Object> userList(String token) {

        //初始化返回值
        Map<String, Object> map = new HashMap<>(3);

        List<User> result = null;

        String errorMsg = "";

        //校验token
        log.info("当前token为:" + token);

        try {
            //验证令牌
            DecodedJWT verify = JWTUtil.verify(token);
            //如果令牌校验成功
            result = userService.userList();
            //返回查询结果
            map.put("code", 200);
            map.put("msg", "查询成功");
            map.put("result", result);
            return map;
        } catch (JWTDecodeException e) {
            //其实是用户修改了header或者payload，但是不用告诉用户错误的细节
            e.printStackTrace();
            errorMsg = "token无效！";
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            //其实是修改了签名，但是不用告诉用户错误的细节
            errorMsg = "token无效！";
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            errorMsg = "token已过期！";
        } catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            //其实是修改了算法，但是不用告诉用户错误的细节
            errorMsg = "token无效！";
        } catch (Exception e) {
            e.printStackTrace();
            errorMsg = "token无效！";
        }
        //返回错误信息
        map.put("code", 500);
        map.put("msg", "token校验失败");
        map.put("result", errorMsg);
        return map;
    }

```



### 使用拦截器优化Token校验

 在前面的案例中，如果每个接口都进行拦截器校验，冗余的代码会非常的多，程序的可读性也非常低。

在单体应用中，可以使用拦截器来校验token

分布式项目中，可以在网关内校验token



#### token拦截器

在上面的案例中，token在body中作为数据传递的，但是这样是不安全的，比较推荐的做法是加在请求头内，通过请求头携带.

```java
package cn.rayfoo.modules.base.interceptor;

import cn.rayfoo.common.util.JWTUtil;
import org.springframework.util.StringUtils;
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


        if(StringUtils.isEmpty(token))
        {
            throw new RuntimeException("无效的token！");
        }
        //验证令牌  如果令牌不正确会出现异常 被全局异常处理
        JWTUtil.verify(token);

        return true;
    }

}

```



#### 拦截器注册

这里我对所有的请求进行了拦截，放行了登录接口，真实的场景下，我们一般会放行所有/user/**的请求，另外，这个拦截器中没有注入其他属性，所以可以通过此种方式创建，如果拦截器内注入了属性，需要使用@Bean+方法的形式注册拦截器。详细的内容，可以参考我博客中关于拦截器的介绍。

```java
package cn.rayfoo.common.config;

import cn.rayfoo.modules.base.interceptor.JWTInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
        .excludePathPatterns("/user/login");

    }

}

```



#### 封装统一返回结果类

接下来的代码我会使用统一结果集来封装返回值，下面是统一结果集的代码：

```java
package cn.rayfoo.common.response;

import lombok.Data;


/**
 * @author rayfoo@qq.com
 * @date 2020年8月6日
 */
@Data
public class Result<T> {

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
    private T data;

    public Result() {
    }

    public Result(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public Result(Integer code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

}
```



#### 全局异常处理

在拦截器中处理异常也是非常不好的习惯，我们可以将异常交由统一异常处理来管理

```java
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


/**
 * @author rayfoo@qq.com
 * @version 1.0
 * <p>全局异常处理</p>
 * @date 2020/8/11 16:36
 */
@ControllerAdvice@Slf4j
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
    @ResponseBody
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
    @ResponseBody
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
    @ResponseBody
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
    @ResponseBody
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
```





####  封装BaseController

这里介绍一个Controller的小技巧，可以通过通用Controller来封装一些公共的属性

```java
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

```



#### Controller代码优化

如果需要用到token中的数据，可以使用request对象中获取token进行相关的处理。下面是优化后的Controller代码，是不是焕然一新呢？

```java
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

```



















参考：http://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html