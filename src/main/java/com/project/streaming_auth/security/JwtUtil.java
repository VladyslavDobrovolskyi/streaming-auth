package com.project.streaming_auth.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

    private final String accessSecretKey;
    private final String refreshSecretKey;

    public JwtUtil(@Value("${jwt.secret}") String accessSecretKey,
                   @Value("${jwt.refresh-secret}") String refreshSecretKey) {
        this.accessSecretKey = accessSecretKey;
        this.refreshSecretKey = refreshSecretKey;
    }

    // Метод для создания Access Token
    public String createAccessToken(String email) {
        Algorithm algorithm = Algorithm.HMAC256(accessSecretKey);
        // Access токен живет 15 минут (900000 мс)
        long ACCESS_TOKEN_EXPIRATION = 900000;
        return JWT.create()
                .withSubject(email)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .sign(algorithm);
    }

    public String createRefreshToken(String email) {
        Algorithm algorithm = Algorithm.HMAC256(refreshSecretKey);
        long REFRESH_TOKEN_EXPIRATION = 604800000;
        return JWT.create()
                .withSubject(email)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .sign(algorithm);
    }

    public String extractEmailFromAccessToken(String token) {
        return JWT.require(Algorithm.HMAC256(accessSecretKey))
                .build()
                .verify(token)
                .getSubject();
    }

    public String extractEmailFromRefreshToken(String token) {
        try {
            return JWT.require(Algorithm.HMAC256(refreshSecretKey))
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException e) {
            System.out.println("Error extracting email from refresh token: " + e.getMessage());
            throw new RuntimeException("Invalid refresh token");
        }
    }

    public boolean isAccessTokenExpired(String token) {
        try {
            Date expirationDate = JWT.require(Algorithm.HMAC256(accessSecretKey))
                    .build()
                    .verify(token)
                    .getExpiresAt();
            return expirationDate.before(new Date());
        } catch (JWTVerificationException e) {
            return true;
        }
    }

    public boolean isRefreshTokenExpired(String token) {
        try {
            Date expirationDate = JWT.require(Algorithm.HMAC256(refreshSecretKey))
                    .build()
                    .verify(token)
                    .getExpiresAt();
            return expirationDate.before(new Date());
        } catch (JWTVerificationException e) {
            System.out.println("Error checking refresh token expiration: " + e.getMessage());
            return true;
        }
    }
}
