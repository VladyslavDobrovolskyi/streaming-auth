package com.project.streaming_auth.controllers;

import com.project.streaming_auth.model.User;
import com.project.streaming_auth.requests.LoginUserRequest;
import com.project.streaming_auth.requests.RegistryUserRequest;
import com.project.streaming_auth.security.JwtUtil;
import com.project.streaming_auth.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
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
        user.setName(request.getName());
        user.setSurname(request.getSurname());
        user.setDob(request.getDob());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setJoinDate(LocalDate.now());

        User createdUser = userService.registerUser(user);
        return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginUserRequest request, HttpServletResponse response) {
        String clientIP = httpServletRequest.getRemoteAddr();
        String requestURI = httpServletRequest.getRequestURI();
        System.out.println("Received login request from IP: " + clientIP + " for URI: " + requestURI);

        User foundUser = userService.findUserByEmail(request.getEmail());

        if (foundUser != null && passwordEncoder.matches(request.getPassword(), foundUser.getPassword())) {
            String accessToken = jwtUtil.createAccessToken(foundUser.getEmail());
            String refreshToken = jwtUtil.createRefreshToken(foundUser.getEmail());
            response.setHeader("Set-Cookie", "refreshToken=" + refreshToken + "; HttpOnly; Secure; SameSite=Strict; Max-Age=604800; Path=/");
            System.out.println("Refresh token: " + refreshToken);
            Map<String, Object> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            return ResponseEntity.ok(tokens);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
        }
    }

    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile() {
        User user = userService.getCurrentUser();

        if (user != null) {
            Map<String, Object> response = new HashMap<>();
            response.put("id", user.getId());
            response.put("email", user.getEmail());
            response.put("joinDate", user.getJoinDate());
            response.put("name", user.getName());
            response.put("fullName", user.getName() + " " + user.getSurname());

            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }
    }

    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteCurrentUser(HttpServletResponse response) {
        User currentUser = userService.getCurrentUser();
        if (currentUser != null) {
            userService.deleteUserById(currentUser.getId());
            SecurityContextHolder.clearContext();
            // Удаление cookies с refreshToken
            Cookie cookie = new Cookie("refreshToken", null);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setMaxAge(0); // Устанавливаем 0 для удаления cookies
            response.addCookie(cookie);
            return ResponseEntity.ok("Account deleted successfully");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated");
        }
    }

}