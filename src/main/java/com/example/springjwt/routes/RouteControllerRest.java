package com.example.springjwt.routes;

import com.example.springjwt.service.JwtService;
import com.example.springjwt.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/test")
public class RouteControllerRest {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;
    @Autowired
    private TokenService tokenService;

    @PostMapping("/login")
    public String login(Authentication authentication) {

        return tokenService.generateToken(authentication);
    }
    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}