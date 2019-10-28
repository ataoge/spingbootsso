package com.chinadci.rdc.ssoclient.controllers;

import org.springframework.security.oauth2.client.DefaultOAuth2RequestAuthenticator;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class HomeController {

    @RequestMapping("/")
    public String index()
    {

        return "home/index";
    }

    @RequestMapping("/about")
    public String about(Principal principal)
    {

        return "home/about.html";
    }
}
