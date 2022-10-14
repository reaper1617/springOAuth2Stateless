package com.gerasimchuk.oauth2mfc.controller;

import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/info")
public class InfoController {


    @GetMapping
    public UserDto info(@CookieValue(name = "SESSION", required = false) String session) {
        return new UserDto(session);
    }

    public static record UserDto(String sessionId) {
    }
}
