package com.chinadci.rdc.ssoserver.config;

import com.alibaba.druid.support.http.StatViewServlet;
import com.alibaba.druid.support.http.WebStatFilter;
import com.chinadci.rdc.ssoserver.services.impl.DaoUserDetailsServiceImpl;
import com.chinadci.rdc.ssoserver.services.impl.MyLdapUserDetailsMapper;
import com.chinadci.rdc.ssoserver.utils.DefaultPasswordEncoderFactories;
import com.chinadci.rdc.ssoserver.utils.NetcorePbkdf2PasswordEncoder;
import org.apache.ibatis.mapping.DatabaseIdProvider;
import org.apache.ibatis.mapping.VendorDatabaseIdProvider;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;

import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;


@Configuration
@EnableWebSecurity
//@Order(1)//SecurityProperties.BASIC_AUTH_ORDER)
@MapperScan("com.chinadci.rdc.ssoserver.repositories")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;



    @Autowired
    public DaoAuthenticationProvider authenticationProvider;

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider authProvider
                = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(myUserDetailsService());
        passwordEncoder = new NetcorePbkdf2PasswordEncoder();
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }


    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.authenticationProvider(authenticationProvider);
        auth.ldapAuthentication()
                //.userDnPatterns("uid={0},ou=people")
                .userSearchBase("ou=用户和组,dc=geo-k,dc=cn")
                .userSearchFilter("(&(objectCategory=Person)(userPrincipalName={0}))")
                .groupSearchBase(null)

                .contextSource()
                .url("ldap://geo-k.cn/")
        .managerDn("CN=test,OU=特殊用户和组,DC=geo-k,DC=cn")
        .managerPassword("test").and().userDetailsContextMapper(ldapUserDetailsMapper());

        auth.inMemoryAuthentication()
                .withUser("user").password(passwordEncoder.encode("chinadci")).roles("USER")
                .and()
                .withUser("rdcAdmin").password(passwordEncoder.encode("85576938")).roles("ADMIN");



    }

    @Bean
    LdapUserDetailsMapper ldapUserDetailsMapper() {
        return new MyLdapUserDetailsMapper();
    }

    @Bean
    UserDetailsService myUserDetailsService() {
        return new DaoUserDetailsServiceImpl();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /*
      实现database Id
     */
    @Bean
    public DatabaseIdProvider getDatabaseIdProvider() {
        DatabaseIdProvider databaseIdProvider = new VendorDatabaseIdProvider();
        Properties p = new Properties();
        p.setProperty("Oracle", "oracle");
        p.setProperty("PostgreSQL","postgresql");
        //p.setProperty("MySQL", "mysql");
        databaseIdProvider.setProperties(p);
        return databaseIdProvider;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                //.antMatchers("/api/**")
                .antMatchers("/resources/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().ignoringAntMatchers("/druid/*")

                .and()
                .antMatcher("/**")
                .authorizeRequests().antMatchers("/", "/login", "/druid/**","/oauth/authorize","/oauth/token").permitAll()
                .antMatchers("/tokens/**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin().permitAll()
                .and().oauth2Login().userInfoEndpoint().userAuthoritiesMapper(userAuthoritiesMapper()).and()
                .and().logout();//.logoutUrl("/signout");
        //DefaultLogoutPageGeneratingFilter
    }

    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (OidcUserAuthority.class.isInstance(authority)) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;

                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                    // Map the claims found in idToken and/or userInfo
                    // to one or more GrantedAuthority's and add it to mappedAuthorities

                } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                    OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;

                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                    // Map the attributes found in userAttributes
                    // to one or more GrantedAuthority's and add it to mappedAuthorities

                }
            });

            return mappedAuthorities;
        };
    }




}
