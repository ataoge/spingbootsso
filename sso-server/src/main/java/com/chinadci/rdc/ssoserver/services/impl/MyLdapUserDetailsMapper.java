package com.chinadci.rdc.ssoserver.services.impl;

import com.chinadci.rdc.ssoserver.models.UserInfo;
import com.chinadci.rdc.ssoserver.repositories.UserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class MyLdapUserDetailsMapper extends LdapUserDetailsMapper {

    @Autowired
    public UserDao userDao;

    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
        UserInfo userInfo = userDao.getUserByName(username);
        if (userInfo != null)
        {

            List<SimpleGrantedAuthority> newAuthorities = new ArrayList<SimpleGrantedAuthority>();
            userInfo.getRoles().forEach((r) -> {
                SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(String.format("ROLE_%s", r.getName()));
                newAuthorities.add(grantedAuthority);
            });
            return super.mapUserFromContext(ctx, username, newAuthorities);

        }
        List<SimpleGrantedAuthority> WhAuthorities = new ArrayList<>();
        // 新建N个角色
        WhAuthorities.add(new SimpleGrantedAuthority("wh01"));
        WhAuthorities.add(new SimpleGrantedAuthority("wh02"));
        WhAuthorities.add(new SimpleGrantedAuthority("wh03"));
        return super.mapUserFromContext(ctx, username, WhAuthorities);
    }


}
