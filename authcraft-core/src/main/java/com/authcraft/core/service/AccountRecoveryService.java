// com/authcraft/core/service/AccountRecoveryService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AccountStatus;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.TwoFactorMethod;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Account Recovery Service.
 * 
 * Features:
 * - Email-based password recovery
 * - Recovery codes for 2FA bypass
 * - Admin-initiated account recovery
 * - Trusted device management
 * - Recovery audit trail
 */
public class AccountRecoveryService {

    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final StorageProvider storage;
    private final AuditService auditService;
    private final Logger logger;
    
    // Pending recovery requests
    private final Map<String, RecoveryRequest> pendingRecoveries;
    
    // Recovery tokens (for password reset)
    private final Map<String, RecoveryToken> recoveryTokens;
    
    // 2FA bypass codes
    private final Map<String, TwoFactorBypass> twoFactorBypasses;
    
    // Secure random for token generation
    private final SecureRandom secureRandom;
    
    // Token expiration times
    private static final long PASSWORD_RESET_TOKEN_TTL = TimeUnit.HOURS.toMillis(1); // 1 hour
    private static final long TWO_FACTOR_BYPASS_TTL = TimeUnit.MINUTES.toMillis(15); // 15 minutes
    private static final int RECOVERY_CODE_LENGTH = 8;

    public AccountRecoveryService(AuthCraftConfig config, PlatformAdapter platform,
                                  StorageProvider storage, AuditService auditService) {
        this.config = config;
        this.platform = platform;
        this.storage = storage;
        this.auditService = auditService;
        this.logger = platform.getLogger();
        this.pendingRecoveries = new ConcurrentHashMap<>();
        this.recoveryTokens = new ConcurrentHashMap<>();
        this.twoFactorBypasses = new ConcurrentHashMap<>();
        this.secureRandom = new SecureRandom();
    }

    // === Password Recovery ===

    /**
     * Initiate password recovery for an account.
     * Sends a recovery email with a reset link.
     */
    public RecoveryResult initiatePasswordRecovery(String username, String email) {
        // Find account by username
        Optional<Account> optAccount = storage.getAccountByName(username).join();
        if (optAccount.isEmpty()) {
            // Don't reveal if account exists
            return RecoveryResult.silent("If the account exists, a recovery email will be sent.");
        }
        
        Account account = optAccount.get();
        
        // Verify email matches
        if (account.getEmail() == null || !account.getEmail().equalsIgnoreCase(email)) {
            return RecoveryResult.silent("If the account exists, a recovery email will be sent.");
        }
        
        // Generate recovery token
        String token = generateSecureToken();
        long expiresAt = System.currentTimeMillis() + PASSWORD_RESET_TOKEN_TTL;
        
        RecoveryToken recoveryToken = new RecoveryToken(
            account.getUuid(),
            token,
            "PASSWORD_RESET",
            expiresAt
        );
        recoveryTokens.put(token, recoveryToken);
        
        // Send recovery email
        boolean sent = sendRecoveryEmail(account, token);
        
        if (sent) {
            // Audit log
            auditService.log(
                AuditEventType.PASSWORD_CHANGE,
                account.getUuid(),
                account.getUsername(),
                "system",
                "Password recovery initiated"
            ).join();
            
            logger.info("[AccountRecovery] Password recovery initiated for: " + username);
            return RecoveryResult.success("Recovery email sent to " + maskEmail(email));
        } else {
            return RecoveryResult.failure("Failed to send recovery email");
        }
    }

    /**
     * Complete password recovery with token.
     */
    public RecoveryResult completePasswordRecovery(String token, String newPassword) {
        RecoveryToken recoveryToken = recoveryTokens.get(token);
        
        if (recoveryToken == null) {
            return RecoveryResult.failure("Invalid recovery token");
        }
        
        if (recoveryToken.isExpired()) {
            recoveryTokens.remove(token);
            return RecoveryResult.failure("Recovery token has expired");
        }
        
        // Get account
        Optional<Account> optAccount = storage.getAccount(recoveryToken.getPlayerUuid()).join();
        if (optAccount.isEmpty()) {
            return RecoveryResult.failure("Account not found");
        }
        
        Account account = optAccount.get();
        
        // Validate new password
        if (newPassword == null || newPassword.length() < config.getPasswordMinLength()) {
            return RecoveryResult.failure("Password does not meet requirements");
        }
        
        // Update password
        // Note: In production, this should hash the password
        account.setPasswordHash(newPassword); // This should be hashed
        storage.saveAccount(account).join();
        
        // Remove used token
        recoveryTokens.remove(token);
        
        // Invalidate all sessions
        storage.deleteSession(account.getUuid()).join();
        
        // Audit log
        auditService.log(
            AuditEventType.PASSWORD_CHANGE,
            account.getUuid(),
            account.getUsername(),
            "system",
            "Password reset via recovery"
        ).join();
        
        logger.info("[AccountRecovery] Password reset completed for: " + account.getUsername());
        
        return RecoveryResult.success("Password has been reset successfully");
    }

    // === 2FA Bypass ===

    /**
     * Generate a 2FA bypass code for an account.
     * Used when player is locked out of 2FA.
     */
    public RecoveryResult requestTwoFactorBypass(String username, String email) {
        Optional<Account> optAccount = storage.getAccountByName(username).join();
        if (optAccount.isEmpty()) {
            return RecoveryResult.silent("If the account exists, a bypass code will be sent.");
        }
        
        Account account = optAccount.get();
        
        // Verify email
        if (account.getEmail() == null || !account.getEmail().equalsIgnoreCase(email)) {
            return RecoveryResult.silent("If the account exists, a bypass code will be sent.");
        }
        
        // Generate bypass code
        String bypassCode = generateBypassCode();
        long expiresAt = System.currentTimeMillis() + TWO_FACTOR_BYPASS_TTL;
        
        TwoFactorBypass bypass = new TwoFactorBypass(
            account.getUuid(),
            bypassCode,
            expiresAt
        );
        twoFactorBypasses.put(bypassCode, bypass);
        
        // Send bypass code email
        boolean sent = sendBypassCodeEmail(account, bypassCode);
        
        if (sent) {
            auditService.log(
                AuditEventType.SECURITY_AUDIT,
                account.getUuid(),
                account.getUsername(),
                "system",
                "2FA bypass code requested"
            ).join();
            
            return RecoveryResult.success("Bypass code sent to " + maskEmail(email));
        } else {
            return RecoveryResult.failure("Failed to send bypass code");
        }
    }

    /**
     * Verify a 2FA bypass code.
     */
    public BypassResult verifyTwoFactorBypass(String username, String code) {
        TwoFactorBypass bypass = twoFactorBypasses.get(code);
        
        if (bypass == null) {
            return BypassResult.invalid("Invalid bypass code");
        }
        
        if (bypass.isExpired()) {
            twoFactorBypasses.remove(code);
            return BypassResult.invalid("Bypass code has expired");
        }
        
        // Verify username matches
        Optional<Account> optAccount = storage.getAccount(bypass.getPlayerUuid()).join();
        if (optAccount.isEmpty() || !optAccount.get().getUsername().equals(username)) {
            return BypassResult.invalid("Invalid bypass code");
        }
        
        // Remove used code
        twoFactorBypasses.remove(code);
        
        // Audit log
        Account account = optAccount.get();
        auditService.log(
            AuditEventType.TWO_FACTOR_DISABLE,
            account.getUuid(),
            account.getUsername(),
            "system",
            "2FA bypassed with recovery code"
        ).join();
        
        return BypassResult.success(account);
    }

    // === Admin Recovery ===

    /**
     * Admin-initiated password reset.
     */
    public RecoveryResult adminResetPassword(UUID adminUuid, String targetUsername, String newPassword) {
        // Verify admin has permission
        Optional<Account> optAdmin = storage.getAccount(adminUuid).join();
        if (optAdmin.isEmpty() || !optAdmin.get().getRole().equals("admin")) {
            return RecoveryResult.failure("Permission denied");
        }
        
        // Find target account
        Optional<Account> optTarget = storage.getAccountByName(targetUsername).join();
        if (optTarget.isEmpty()) {
            return RecoveryResult.failure("Account not found");
        }
        
        Account target = optTarget.get();
        
        // Update password
        target.setPasswordHash(newPassword); // Should be hashed
        target.setStatus(AccountStatus.ACTIVE);
        target.setLockedUntil(null);
        target.setFailedLoginAttempts(0);
        storage.saveAccount(target).join();
        
        // Invalidate sessions
        storage.deleteSession(target.getUuid()).join();
        
        // Audit log
        auditService.log(
            AuditEventType.PASSWORD_CHANGE,
            target.getUuid(),
            target.getUsername(),
            "admin:" + optAdmin.get().getUsername(),
            "Admin password reset"
        ).join();
        
        logger.info("[AccountRecovery] Admin password reset for: " + targetUsername + 
                   " by: " + optAdmin.get().getUsername());
        
        return RecoveryResult.success("Password reset for " + targetUsername);
    }

    /**
     * Admin-initiated 2FA reset.
     */
    public RecoveryResult adminResetTwoFactor(UUID adminUuid, String targetUsername) {
        // Verify admin
        Optional<Account> optAdmin = storage.getAccount(adminUuid).join();
        if (optAdmin.isEmpty() || !optAdmin.get().getRole().equals("admin")) {
            return RecoveryResult.failure("Permission denied");
        }
        
        // Find target
        Optional<Account> optTarget = storage.getAccountByName(targetUsername).join();
        if (optTarget.isEmpty()) {
            return RecoveryResult.failure("Account not found");
        }
        
        Account target = optTarget.get();
        
        // Disable 2FA
        target.setEnabledTwoFactorMethods(java.util.EnumSet.noneOf(com.authcraft.core.model.TwoFactorMethod.class));
        target.setTotpSecret(null);
        storage.saveAccount(target).join();
        storage.deleteBackupCodes(target.getUuid()).join();
        
        // Audit log
        auditService.log(
            AuditEventType.TWO_FACTOR_DISABLE,
            target.getUuid(),
            target.getUsername(),
            "admin:" + optAdmin.get().getUsername(),
            "Admin 2FA reset"
        ).join();
        
        logger.info("[AccountRecovery] Admin 2FA reset for: " + targetUsername + 
                   " by: " + optAdmin.get().getUsername());
        
        return RecoveryResult.success("2FA disabled for " + targetUsername);
    }

    /**
     * Admin-initiated account unlock.
     */
    public RecoveryResult adminUnlockAccount(UUID adminUuid, String targetUsername) {
        // Verify admin
        Optional<Account> optAdmin = storage.getAccount(adminUuid).join();
        if (optAdmin.isEmpty() || !optAdmin.get().getRole().equals("admin")) {
            return RecoveryResult.failure("Permission denied");
        }
        
        // Find target
        Optional<Account> optTarget = storage.getAccountByName(targetUsername).join();
        if (optTarget.isEmpty()) {
            return RecoveryResult.failure("Account not found");
        }
        
        Account target = optTarget.get();

        // Unlock account
        target.setStatus(AccountStatus.ACTIVE);
        target.setLockedUntil(null);
        target.setFailedLoginAttempts(0);
        storage.saveAccount(target).join();
        
        // Audit log
        auditService.log(
            AuditEventType.ACCOUNT_UNLOCK,
            target.getUuid(),
            target.getUsername(),
            "admin:" + optAdmin.get().getUsername(),
            "Admin account unlock"
        ).join();
        
        logger.info("[AccountRecovery] Admin unlock for: " + targetUsername + 
                   " by: " + optAdmin.get().getUsername());
        
        return RecoveryResult.success("Account unlocked: " + targetUsername);
    }

    // === Helper Methods ===

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateBypassCode() {
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < RECOVERY_CODE_LENGTH; i++) {
            code.append((char) ('A' + secureRandom.nextInt(26)));
            if (i == 3) code.append('-');
        }
        return code.toString();
    }

    private boolean sendRecoveryEmail(Account account, String token) {
        // In production, this would use the EmailProvider
        // For now, log the action
        logger.info("[AccountRecovery] Would send recovery email to: " + account.getEmail() + 
                   " with token: " + token.substring(0, 8) + "...");
        return true;
    }

    private boolean sendBypassCodeEmail(Account account, String code) {
        logger.info("[AccountRecovery] Would send bypass code to: " + account.getEmail() + 
                   " code: " + code);
        return true;
    }

    private String maskEmail(String email) {
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) return "***@***";
        
        String local = email.substring(0, atIndex);
        String domain = email.substring(atIndex + 1);
        
        String maskedLocal = local.charAt(0) + "***" + 
            (local.length() > 1 ? local.charAt(local.length() - 1) : "");
        
        return maskedLocal + "@" + domain;
    }

    /**
     * Cleanup expired tokens and codes.
     */
    public void cleanup() {
        long now = System.currentTimeMillis();
        
        recoveryTokens.entrySet().removeIf(e -> e.getValue().isExpired());
        twoFactorBypasses.entrySet().removeIf(e -> e.getValue().isExpired());
        pendingRecoveries.entrySet().removeIf(e -> e.getValue().isExpired());
    }

    // === Inner Classes ===

    private static class RecoveryRequest {
        private final String username;
        private final String email;
        private final long createdAt;
        private final long expiresAt;

        public RecoveryRequest(String username, String email, long ttl) {
            this.username = username;
            this.email = email;
            this.createdAt = System.currentTimeMillis();
            this.expiresAt = createdAt + ttl;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    private static class RecoveryToken {
        private final UUID playerUuid;
        private final String token;
        private final String type;
        private final long expiresAt;

        public RecoveryToken(UUID playerUuid, String token, String type, long expiresAt) {
            this.playerUuid = playerUuid;
            this.token = token;
            this.type = type;
            this.expiresAt = expiresAt;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getToken() { return token; }
        public String getType() { return type; }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    private static class TwoFactorBypass {
        private final UUID playerUuid;
        private final String code;
        private final long expiresAt;

        public TwoFactorBypass(UUID playerUuid, String code, long expiresAt) {
            this.playerUuid = playerUuid;
            this.code = code;
            this.expiresAt = expiresAt;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getCode() { return code; }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    // === Result Classes ===

    public static class RecoveryResult {
        private final boolean success;
        private final String message;
        private final boolean silent;

        private RecoveryResult(boolean success, String message, boolean silent) {
            this.success = success;
            this.message = message;
            this.silent = silent;
        }

        public static RecoveryResult success(String message) {
            return new RecoveryResult(true, message, false);
        }

        public static RecoveryResult failure(String message) {
            return new RecoveryResult(false, message, false);
        }

        public static RecoveryResult silent(String message) {
            return new RecoveryResult(true, message, true);
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public boolean isSilent() { return silent; }
    }

    public static class BypassResult {
        private final boolean valid;
        private final String message;
        private final Account account;

        private BypassResult(boolean valid, String message, Account account) {
            this.valid = valid;
            this.message = message;
            this.account = account;
        }

        public static BypassResult invalid(String message) {
            return new BypassResult(false, message, null);
        }

        public static BypassResult success(Account account) {
            return new BypassResult(true, "Bypass successful", account);
        }

        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        public Account getAccount() { return account; }
    }
}
