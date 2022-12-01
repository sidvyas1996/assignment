package com.emeritus.assignment.controller;

import com.emeritus.assignment.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class JWTController {

        @Autowired
        private TokenService tokenService;


        @PostMapping("/token")
        public ResponseEntity<?> authenticate(Authentication authentication) throws Exception {
        log.debug("Token for requested user {}"+ authentication.getName());
        String token = tokenService.generateToken(authentication);
        return ResponseEntity.ok(token);
        }

    }


