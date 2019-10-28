package com.chinadci.rdc.ssoserver.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;

@Controller
public class OauthController {

    @RequestMapping("oauth/exit")
    public void exit(HttpServletRequest request, HttpServletResponse response) {
        // token can be revoked here if needed
        new SecurityContextLogoutHandler().logout(request, null, null);
        try {
            //sending back to client app
            response.sendRedirect(request.getHeader("referer"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @RequestMapping("/signout")
    public void signout(HttpServletRequest request, HttpServletResponse response) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof DefaultOidcUser) {

            DefaultOidcUser authority = (DefaultOidcUser) principal;
            String idToken = authority.getIdToken().getTokenValue();
            String post_logout_redirect_uri = "http://localhost:8080/javasso/";

            try {
                SecurityContextHolder.clearContext();
                String url = String.format("https://login.chinadci.com/connect/endsession?id_token_hint=%s&post_logout_redirect_uri=%s", idToken, URLEncoder.encode(post_logout_redirect_uri, StandardCharsets.UTF_8.toString()));
                response.sendRedirect(url);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        else
        {
            try {
                response.sendRedirect("/logout");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}
