package com.microservice.authserver.controller;

import com.microservice.authserver.dto.LoginRequest;
import com.microservice.authserver.dto.TokenResponse;
import com.microservice.authserver.service.OAuth2TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private OAuth2TokenService oAuth2TokenService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
        try {
            TokenResponse tokenResponse = oAuth2TokenService.generateAccessToken(loginRequest);
            return ResponseEntity.ok(tokenResponse);
        }catch (AuthenticationException ex){
            Map<String, String> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Invalid credentials");
            return ResponseEntity.badRequest().body(error);
        }
    }
}
