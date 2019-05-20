package com.java2e.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author: liangcan
 * @version: 1.0
 * @date: 2019/5/20 17:45
 * @describtion: ResourceApplication
 */
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
