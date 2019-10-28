package com.chinadci.rdc.ssoclient.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;

@Configuration
@EnableOAuth2Sso
public class WebSecurityConfig  extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
                .authorizeRequests()
                //.antMatchers("/error").permitAll()
                .antMatchers("/","/login**","/error")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and().oauth2Login();//.userInfoEndpoint().userService(new DefaultOAuth2UserService());

    }
}
