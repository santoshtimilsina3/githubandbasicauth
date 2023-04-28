package com.santosh.springsecOAUTH2GitHub.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class SecureController {

    @GetMapping("/")
    public String main(Authentication authentication) {
        System.out.println(authentication.getName());
        return "secure.html";
    }

}
