# auth2-auth-resource-sso
## 实现一个最基本的OAuth2认证+资源+sso服务

项目使用3个独立的工程分别实现认证服务(auth)、资源服务器(resource)和单点登陆服务器(sso)

这绝对是全网最全面的，最简单的教程了

项目需要的环境
 - maven
 - jdk8
 - idea

github地址：https://github.com/whaty/auth2-auth-resource-sso

## 新建一个项目，添加项目依赖：

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.java2e</groupId>
    <artifactId>auth2.0-sso</artifactId>
    <packaging>pom</packaging>
    <version>1.0-SNAPSHOT</version>
    <modules>
        <module>auth</module>
        <module>resource</module>
        <module>sso</module>
    </modules>

    <properties>
        <spring-boot.version>2.1.3.RELEASE</spring-boot.version>
        <spring-cloud.version>Greenwich.RELEASE</spring-cloud.version>
        <spring-platform.version>Cairo-SR7</spring-platform.version>
        <java.version>1.8</java.version>
        <resource.delimiter>@</resource.delimiter>
        <maven.compiler.source>${java.version}</maven.compiler.source>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.target>${java.version}</maven.compiler.target>
    </properties>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.3.RELEASE</version>
    </parent>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security.oauth.boot</groupId>
            <artifactId>spring-security-oauth2-autoconfigure</artifactId>
            <version>2.1.2.RELEASE</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>2.3.2</version>
                <configuration>
                    <source>1.8</source>
                    <target>1.8</target>
                    <encoding>UTF-8</encoding>
                </configuration>
            </plugin>
            <!--打包-->
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <executions>
                    <execution>
                        <goals>
                            <goal>repackage</goal><!--把依赖的包都打包到生成的Jar包中-->
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>

</project>
```

## 新建auth模块
 **1、pom.xml：**

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>auth2.0-sso</artifactId>
        <groupId>com.java2e</groupId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>auth</artifactId>
    <packaging>jar</packaging>
    <description>认证中心</description>

</project>
```
**2、启动类**

```
@SpringBootApplication
@EnableAuthorizationServer
public class AuthApplication {
    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthApplication.class)
                .run(args);
    }
}
```
**3、AuthorizationServerConfigurer**

```
@Configuration
public class AuthorizationServerConfigurer extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        /* 配置token获取合验证时的策略 */
        security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 配置oauth2的 client信息
        // authorizedGrantTypes 有4种，这里只开启2种
        // secret密码配置从 Spring Security 5.0开始必须以 {bcrypt}+加密后的密码 这种格式填写
        clients.inMemory()
                .withClient("client1")
                .secret(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("123456"))
                .scopes("test").authorizedGrantTypes("authorization_code", "refresh_token")
        .redirectUris("http://127.0.0.1:8085/login").autoApprove("true");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 配置tokenStore
        endpoints.authenticationManager(authenticationManager).tokenStore(memoryTokenStore());
    }

    // 使用最基本的InMemoryTokenStore生成token
    @Bean
    public TokenStore memoryTokenStore() {
        return new InMemoryTokenStore();
    }
}

```

**注意：redirectUris一定要写成127.0.0.1，因为：sso和auth域名相同时，浏览器会使用同一个cookie导致页面一直再login页重定向，所以需要把认证服务器和sso客户端设置为不同域名下启动。**


**4、WebSecurityConfigurer**

```
@EnableWebSecurity
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {
    // 配置这个bean会在做AuthorizationServerConfigurer配置的时候使用
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("admin"))
                .roles("test")
        ;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                authorizeRequests().
                antMatchers("/oauth/**")
                .permitAll()
                .and()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .formLogin()
        .and().csrf().disable();
    }
}

```
**到此为止，auth需要的东西已经足够了，有的教程写的东西太杂了，反倒误导人**

## 新建resource模块
**1、pom.xml**

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>auth2.0-sso</artifactId>
        <groupId>com.java2e</groupId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>resource</artifactId>
    <packaging>jar</packaging>
    <description>资源服务器</description>

</project>
```

**2、启动类**

```
@SpringBootApplication
@EnableResourceServer
@RestController
public class ResourceApplication {
    public static void main(String[] args) {
        new SpringApplicationBuilder(ResourceApplication.class)
                .run(args);
    }

    // 添加一个测试访问接口
    @GetMapping("/user")
    public Authentication getUser(Authentication authentication) {
        System.out.println("resource: user {}"+ authentication);
        return authentication;
    }
}

```
**3、配置文件**

```
auth-server: http://localhost:8080 # 认证服务器地址

server:
  port: 8086

security:
  oauth2:
    client:
      client-id: client1 # 授权服务器配置的client id
      client-secret: 123456 # 授权服务器配置的client secret
      scope: test
      access-token-uri: ${auth-server}/oauth/token # 获取access token接口
      user-authorization-uri: ${auth-server}/oauth/authorize #  获取Authorization Code接口
    resource:
      token-info-uri: ${auth-server}/oauth/check_token # 验证token的接口
```
**到此为止，resource需要的东西已经足够了**

## 新建sso模块
**1、pom.xml**

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>auth2.0-sso</artifactId>
        <groupId>com.java2e</groupId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>sso</artifactId>


</project>
```

**2、启动类**

```
@EnableOAuth2Sso
@SpringBootApplication
@RestController
public class SsoApplication {
    private static final Logger log = LoggerFactory.getLogger(SsoApplication.class);

    public static void main(String[] args) {
        new SpringApplicationBuilder(SsoApplication.class)
                .run(args);
    }

    // sso测试接口
    @GetMapping("/user")
    public Authentication getUser(Authentication authentication) {
        log.info("auth : {}", authentication);
        return authentication;

    }
}


```
**3、配置文件**

```
auth-server: http://localhost:8080 # 认证服务器地址

server:
  port: 8085

security:
  oauth2:
    client:
      client-id: client1 # 授权服务器配置的client id
      client-secret: 123456 # 授权服务器配置的client secret
      scope: test
      access-token-uri: ${auth-server}/oauth/token # 获取access token接口
      user-authorization-uri: ${auth-server}/oauth/authorize #  获取Authorization Code接口
    resource:
      token-info-uri: ${auth-server}/oauth/check_token # 验证token的接口
```
**到此为止，sso需要的东西已经足够了**

## 下面开始测试，验证
1、浏览器访问：http://127.0.0.1:8085/user ，输入admin/admin，这一步走单点登录认证
![在这里插入图片描述](https://img-blog.csdnimg.cn/2019052019145885.gif)
2、用上面返回的tokenvalue访问：http://localhost:8086/user ，这一步是访问的resource服务器![在这里插入图片描述](https://img-blog.csdnimg.cn/20190520191621204.gif)
**到此为止，一个完整的认证+资源+单点流程已经跑通了，这绝对是全网最全面的，最简单的教程了**

**一些基本概念扫盲：**

http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html
http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html
