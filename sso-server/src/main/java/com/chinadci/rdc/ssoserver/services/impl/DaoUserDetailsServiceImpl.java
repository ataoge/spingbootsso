package com.chinadci.rdc.ssoserver.services.impl;

import com.chinadci.rdc.ssoserver.models.UserInfo;
import com.chinadci.rdc.ssoserver.repositories.UserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;



import org.springframework.stereotype.Service;


import java.util.*;


@Service
public class DaoUserDetailsServiceImpl implements UserDetailsService {


    private BCryptPasswordEncoder passwordEncoder=new BCryptPasswordEncoder();

    @Autowired
    public UserDao userDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username.endsWith("geo-k.cn"))
            throw new UsernameNotFoundException("not in database!");

        UserInfo userInfo = userDao.getUserByName(username);

        if (userInfo != null && !userInfo.getUserName().endsWith("geo-k.cn")) {


            // 封装用户信息，并返回。参数分别是：用户名，密码，用户权限
            String encode = passwordEncoder.encode("123456");
            //123456   "$2a$10$rE5.RvkHaB06t.9GjGeaW.jNHysRQpBXObl3ZSahzBesfq7tAkX56"
            List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
            userInfo.getRoles().forEach((r) -> {
                SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(String.format("ROLE_%s", r.getName()));
                authorities.add(grantedAuthority);
            });
            UserDetails user = new User(username, userInfo.getPasswordhash(), authorities);


            return user;

        }

        throw new UsernameNotFoundException("not in database!");
    }



}
