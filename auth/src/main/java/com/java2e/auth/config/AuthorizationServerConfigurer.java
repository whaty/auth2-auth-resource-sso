package com.java2e.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author: liangcan
 * @version: 1.0
 * @date: 2019/5/20 17:40
 * @describtion: AuthorizationServerConfigurer
 */
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
