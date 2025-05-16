package com.project.streaming_auth.controllers;

import com.project.streaming_auth.model.User;
import com.project.streaming_auth.requests.LoginUserRequest;
import com.project.streaming_auth.requests.RegistryUserRequest;
import com.project.streaming_auth.security.JwtUtil;
import com.project.streaming_auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final HttpServletRequest httpServletRequest;

    @Autowired
    public UserController(UserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, HttpServletRequest httpServletRequest) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.httpServletRequest = httpServletRequest;
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@Valid @RequestBody RegistryUserRequest request) {
        User user = new User();
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setUsername(request.getUsername());
        User createdUser = userService.registerUser(user);
        return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginUserRequest request, HttpServletResponse response) {
        String clientIP = httpServletRequest.getRemoteAddr();
        String requestURI = httpServletRequest.getRequestURI();
        System.out.println("Received login request from IP: " + clientIP + " for URI: " + requestURI);

  

        User foundUser = userService.findUserByUsername(request.getUsername());

        System.out.println("Found user: " + foundUser);

        
        if (Objects.nonNull(foundUser) && passwordEncoder.matches(request.getPassword(), foundUser.getPassword())) {
            String accessToken = jwtUtil.createAccessToken(foundUser.getUsername());
            String refreshToken = jwtUtil.createRefreshToken(foundUser.getUsername());
            System.out.println("Access token: " + accessToken);
            System.out.println("Refresh token: " + refreshToken);
            response.setHeader("Set-Cookie", "refreshToken=" + refreshToken + "; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/");
            System.out.println("Refresh token: " + refreshToken);
            Map<String, Object> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            return ResponseEntity.ok(tokens);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
        }
    
    }
    
}