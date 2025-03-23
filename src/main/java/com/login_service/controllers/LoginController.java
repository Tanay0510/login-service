package com.login_service.controllers;

import com.login_service.models.User;
import com.login_service.services.UserService;
import com.login_service.utils.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    private static final Logger logger = LoggerFactory.getLogger(LoginController.class); // Logger instance



    public LoginController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        logger.info("Attempting to register user with email: {}", user.getEmail());
        userService.register(user);
        logger.info("Successfully registered user with email: {}", user.getEmail());
        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest request) {
        logger.info("Login attempt for email: {}", request.getEmail());
        User user = userService.authenticate(request.getEmail(), request.getPassword());
        String token = jwtUtil.generateToken(user.getEmail());
        logger.info("Login successful for email: {}", request.getEmail());
        return ResponseEntity.ok(Map.of("token", token));
    }
}


class LoginRequest {
    private String email;
    private String password;

    // Getters and setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
