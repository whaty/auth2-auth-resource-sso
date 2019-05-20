package com.java2e.sso;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author: liangcan
 * @version: 1.0
 * @date: 2019/5/20 18:09
 * @describtion: SsoApplication
 *
 * sso再域名相同时浏览器会使用同一个cookie导致页面一直再login页重定向，所以需要把认证服务器和sso客户端设置为不同域名下启动。
 */
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
