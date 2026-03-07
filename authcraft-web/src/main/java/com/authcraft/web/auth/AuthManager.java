package com.authcraft.web.auth;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.Role;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.web.ApiResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authentication manager for web dashboard.
 * Handles login, logout, token validation, and session management.
 */
public class AuthManager {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthManager.class);
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
    
    private final AuthCraftCore core;
    private final JwtManager jwtManager;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    // Rate limiting: IP -> (attempts, lastAttempt)
    private final Map<String, LoginAttempts> loginAttempts = new ConcurrentHashMap<>();
    
    // Active sessions: token -> session info
    private final Map<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();
    
    public AuthManager(AuthCraftCore core, JwtManager jwtManager) {
        this.core = core;
        this.jwtManager = jwtManager;
    }
    
    /**
     * Handle login request.
     */
    public void handleLogin(Context ctx) {
        try {
            LoginRequest request = ctx.bodyAsClass(LoginRequest.class);
            String clientIp = getClientIp(ctx);
            
            // Check rate limiting
            if (isRateLimited(clientIp)) {
                ctx.status(429).json(ApiResponse.error("Too many login attempts. Please try again later."));
                return;
            }
            
            // Validate credentials
            Optional<Account> optAccount = validateCredentials(request.username, request.password);
            
            if (optAccount.isEmpty()) {
                recordFailedAttempt(clientIp);
                ctx.status(401).json(ApiResponse.error("Invalid credentials"));
                return;
            }
            
            Account account = optAccount.get();
            
            // Check if account has admin access
            if (!hasAdminAccess(account)) {
                recordFailedAttempt(clientIp);
                ctx.status(403).json(ApiResponse.error("Access denied. Admin privileges required."));
                return;
            }
            
            // Clear failed attempts on successful login
            clearFailedAttempts(clientIp);
            
            // Generate tokens
            String role = getRoleName(account);
            JwtManager.TokenPair tokens = jwtManager.generateTokenPair(account.getUsername(), role);
            
            // Store session
            SessionInfo session = new SessionInfo(
                account.getUuid(),
                account.getUsername(),
                role,
                System.currentTimeMillis()
            );
            activeSessions.put(tokens.getAccessToken(), session);
            
            // Build response
            Map<String, Object> userData = new HashMap<>();
            userData.put("username", account.getUsername());
            userData.put("role", role);
            userData.put("accessToken", tokens.getAccessToken());
            userData.put("refreshToken", tokens.getRefreshToken());
            userData.put("expiresIn", 15 * 60); // 15 minutes in seconds
            
            logger.info("Web dashboard login: {} from {}", account.getUsername(), clientIp);
            
            ctx.json(ApiResponse.success("Login successful", userData));
            
        } catch (Exception e) {
            logger.error("Login error", e);
            ctx.status(500).json(ApiResponse.error("Internal server error"));
        }
    }
    
    /**
     * Handle logout request.
     */
    public void handleLogout(Context ctx) {
        try {
            String authHeader = ctx.header("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                jwtManager.invalidateToken(token);
                activeSessions.remove(token);
            }
            
            ctx.json(ApiResponse.success("Logged out successfully"));
            
        } catch (Exception e) {
            logger.error("Logout error", e);
            ctx.status(500).json(ApiResponse.error("Internal server error"));
        }
    }
    
    /**
     * Handle token verification.
     */
    public void handleVerify(Context ctx) {
        try {
            String authHeader = ctx.header("Authorization");
            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                ctx.status(401).json(ApiResponse.error("No token provided"));
                return;
            }
            
            String token = authHeader.substring(7);
            var claims = jwtManager.validateToken(token);
            
            if (claims == null) {
                ctx.status(401).json(ApiResponse.error("Invalid or expired token"));
                return;
            }
            
            SessionInfo session = activeSessions.get(token);
            if (session == null) {
                ctx.status(401).json(ApiResponse.error("Session not found"));
                return;
            }
            
            Map<String, Object> userData = new HashMap<>();
            userData.put("username", session.username);
            userData.put("role", session.role);
            userData.put("valid", true);
            
            ctx.json(ApiResponse.success("Token valid", userData));
            
        } catch (Exception e) {
            logger.error("Token verification error", e);
            ctx.status(500).json(ApiResponse.error("Internal server error"));
        }
    }
    
    /**
     * Handle token refresh.
     */
    public void handleRefresh(Context ctx) {
        try {
            RefreshRequest request = ctx.bodyAsClass(RefreshRequest.class);
            
            if (!jwtManager.isRefreshToken(request.refreshToken)) {
                ctx.status(401).json(ApiResponse.error("Invalid refresh token"));
                return;
            }
            
            String username = jwtManager.getUsername(request.refreshToken);
            if (username == null) {
                ctx.status(401).json(ApiResponse.error("Invalid or expired refresh token"));
                return;
            }
            
            // Get account to retrieve role
            StorageProvider storage = core.getStorage();
            Optional<Account> optAccount = storage.getAccountByName(username).join();
            
            if (optAccount.isEmpty()) {
                ctx.status(401).json(ApiResponse.error("Account not found"));
                return;
            }
            
            Account account = optAccount.get();
            String role = getRoleName(account);
            
            // Generate new tokens
            JwtManager.TokenPair tokens = jwtManager.generateTokenPair(username, role);
            
            // Invalidate old refresh token
            jwtManager.invalidateToken(request.refreshToken);
            
            // Update session
            SessionInfo session = new SessionInfo(
                account.getUuid(),
                account.getUsername(),
                role,
                System.currentTimeMillis()
            );
            activeSessions.put(tokens.getAccessToken(), session);
            
            Map<String, Object> tokenData = new HashMap<>();
            tokenData.put("accessToken", tokens.getAccessToken());
            tokenData.put("refreshToken", tokens.getRefreshToken());
            tokenData.put("expiresIn", 15 * 60);
            
            ctx.json(ApiResponse.success("Token refreshed", tokenData));
            
        } catch (Exception e) {
            logger.error("Token refresh error", e);
            ctx.status(500).json(ApiResponse.error("Internal server error"));
        }
    }
    
    /**
     * Middleware to require authentication.
     */
    public void requireAuth(Context ctx) {
        String authHeader = ctx.header("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            ctx.status(401).json(ApiResponse.error("Authentication required"));
            return;
        }
        
        String token = authHeader.substring(7);
        var claims = jwtManager.validateToken(token);
        
        if (claims == null) {
            ctx.status(401).json(ApiResponse.error("Invalid or expired token"));
            return;
        }
        
        // Store user info in context for later use
        ctx.attribute("username", claims.getSubject());
        ctx.attribute("role", claims.get("role", String.class));
    }
    
    /**
     * Validate credentials against stored accounts.
     */
    private Optional<Account> validateCredentials(String username, String password) {
        try {
            StorageProvider storage = core.getStorage();
            Optional<Account> optAccount = storage.getAccountByName(username).join();
            
            if (optAccount.isEmpty()) {
                return Optional.empty();
            }
            
            Account account = optAccount.get();
            
            // Verify password
            boolean valid = core.verifyPassword(password, account.getPasswordHash(), account.getHashAlgorithm());
            
            if (!valid) {
                return Optional.empty();
            }
            
            // Check if account is locked
            if (account.isLocked()) {
                return Optional.empty();
            }
            
            return Optional.of(account);
            
        } catch (Exception e) {
            logger.error("Error validating credentials", e);
            return Optional.empty();
        }
    }
    
    /**
     * Check if account has admin access.
     */
    private boolean hasAdminAccess(Account account) {
        String role = account.getRole();
        if (role == null) {
            return false;
        }

        // Check for admin or moderator role
        String roleName = role.toLowerCase();
        return roleName.equals("admin") ||
               roleName.equals("moderator") ||
               roleName.equals("owner");
    }

    /**
     * Get role name from account.
     */
    private String getRoleName(Account account) {
        String role = account.getRole();
        return role != null ? role : "player";
    }
    
    /**
     * Check if IP is rate limited.
     */
    private boolean isRateLimited(String ip) {
        LoginAttempts attempts = loginAttempts.get(ip);
        if (attempts == null) {
            return false;
        }
        
        // Check if lockout has expired
        if (System.currentTimeMillis() - attempts.lastAttempt > LOCKOUT_DURATION) {
            loginAttempts.remove(ip);
            return false;
        }
        
        return attempts.count >= MAX_LOGIN_ATTEMPTS;
    }
    
    /**
     * Record a failed login attempt.
     */
    private void recordFailedAttempt(String ip) {
        loginAttempts.compute(ip, (key, attempts) -> {
            if (attempts == null) {
                return new LoginAttempts(1, System.currentTimeMillis());
            }
            return new LoginAttempts(attempts.count + 1, System.currentTimeMillis());
        });
    }
    
    /**
     * Clear failed attempts for an IP.
     */
    private void clearFailedAttempts(String ip) {
        loginAttempts.remove(ip);
    }
    
    /**
     * Get client IP from request.
     */
    private String getClientIp(Context ctx) {
        String forwarded = ctx.header("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) {
            return forwarded.split(",")[0].trim();
        }
        return ctx.ip();
    }
    
    // Helper classes
    
    private static class LoginAttempts {
        final int count;
        final long lastAttempt;
        
        LoginAttempts(int count, long lastAttempt) {
            this.count = count;
            this.lastAttempt = lastAttempt;
        }
    }
    
    private static class SessionInfo {
        final UUID uuid;
        final String username;
        final String role;
        final long createdAt;
        
        SessionInfo(UUID uuid, String username, String role, long createdAt) {
            this.uuid = uuid;
            this.username = username;
            this.role = role;
            this.createdAt = createdAt;
        }
    }
    
    // Request DTOs
    
    public static class LoginRequest {
        public String username;
        public String password;
    }
    
    public static class RefreshRequest {
        public String refreshToken;
    }
}
