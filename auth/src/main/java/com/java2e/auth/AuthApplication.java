package com.java2e.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * @author: liangcan
 * @version: 1.0
 * @date: 2019/5/20 17:38
 * @describtion: AuthApplication
 */
@SpringBootApplication
@EnableAuthorizationServer
public class AuthApplication {
    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthApplication.class)
                .run(args);
    }
}
