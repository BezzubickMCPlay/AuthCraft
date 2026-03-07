package com.authcraft.web.auth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JWT token manager for web dashboard authentication.
 * Handles token generation, validation, and refresh.
 */
public class JwtManager {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtManager.class);
    private static final long ACCESS_TOKEN_VALIDITY = 15 * 60 * 1000; // 15 minutes
    private static final long REFRESH_TOKEN_VALIDITY = 7 * 24 * 60 * 60 * 1000; // 7 days
    
    private final SecretKey secretKey;
    private final Map<String, Long> tokenBlacklist = new ConcurrentHashMap<>();
    
    public JwtManager(String secret) {
        // Ensure the secret is long enough for HS256
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            // Pad the key if it's too short
            byte[] paddedKey = new byte[32];
            System.arraycopy(keyBytes, 0, paddedKey, 0, keyBytes.length);
            keyBytes = paddedKey;
        }
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }
    
    /**
     * Generate an access token for a user.
     */
    public String generateAccessToken(String username, String role) {
        return Jwts.builder()
            .subject(username)
            .claim("role", role)
            .claim("type", "access")
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
            .signWith(secretKey)
            .compact();
    }
    
    /**
     * Generate a refresh token for a user.
     */
    public String generateRefreshToken(String username) {
        return Jwts.builder()
            .subject(username)
            .claim("type", "refresh")
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
            .signWith(secretKey)
            .compact();
    }
    
    /**
     * Validate a token and extract claims.
     */
    public Claims validateToken(String token) {
        try {
            // Check blacklist first
            if (tokenBlacklist.containsKey(token)) {
                return null;
            }
            
            Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
            
            // Check expiration
            if (claims.getExpiration().before(new Date())) {
                return null;
            }
            
            return claims;
            
        } catch (JwtException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Extract username from token.
     */
    public String getUsername(String token) {
        Claims claims = validateToken(token);
        return claims != null ? claims.getSubject() : null;
    }
    
    /**
     * Extract role from token.
     */
    public String getRole(String token) {
        Claims claims = validateToken(token);
        return claims != null ? claims.get("role", String.class) : null;
    }
    
    /**
     * Check if token is an access token.
     */
    public boolean isAccessToken(String token) {
        Claims claims = validateToken(token);
        return claims != null && "access".equals(claims.get("type", String.class));
    }
    
    /**
     * Check if token is a refresh token.
     */
    public boolean isRefreshToken(String token) {
        Claims claims = validateToken(token);
        return claims != null && "refresh".equals(claims.get("type", String.class));
    }
    
    /**
     * Invalidate a token (add to blacklist).
     */
    public void invalidateToken(String token) {
        tokenBlacklist.put(token, System.currentTimeMillis());
        cleanupBlacklist();
    }
    
    /**
     * Clean up expired tokens from blacklist.
     */
    private void cleanupBlacklist() {
        long now = System.currentTimeMillis();
        tokenBlacklist.entrySet().removeIf(entry -> 
            (now - entry.getValue()) > REFRESH_TOKEN_VALIDITY);
    }
    
    /**
     * Generate token pair (access + refresh).
     */
    public TokenPair generateTokenPair(String username, String role) {
        return new TokenPair(
            generateAccessToken(username, role),
            generateRefreshToken(username)
        );
    }
    
    /**
     * Token pair container.
     */
    public static class TokenPair {
        private final String accessToken;
        private final String refreshToken;
        
        public TokenPair(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
        
        public String getAccessToken() {
            return accessToken;
        }
        
        public String getRefreshToken() {
            return refreshToken;
        }
    }
}
