// com/authcraft/core/model/Account.java
package com.authcraft.core.model;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

public class Account {

    private UUID uuid;
    private String username;
    private String normalizedUsername;
    private String passwordHash;
    private HashAlgorithm hashAlgorithm;
    private AccountStatus status;
    private String email;
    private String role;

    // 2FA - Support for multiple methods
    private Set<TwoFactorMethod> enabledTwoFactorMethods;
    private String totpSecret;
    private String telegramChatId;
    private String vkUserId;
    private String emailVerificationCode;

    // Security
    private int failedLoginAttempts;
    private Instant lockedUntil;
    private String registrationIp;
    private String lastLoginIp;
    private Instant lastLoginDate;
    private Instant createdAt;
    private Instant updatedAt;

    public Account() {
        this.status = AccountStatus.PENDING_REGISTRATION;
        this.hashAlgorithm = HashAlgorithm.ARGON2ID;
        this.enabledTwoFactorMethods = EnumSet.noneOf(TwoFactorMethod.class);
        this.failedLoginAttempts = 0;
        this.role = "guest";
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    // === Getters & Setters ===

    public UUID getUuid() { return uuid; }
    public void setUuid(UUID uuid) { this.uuid = uuid; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getNormalizedUsername() { return normalizedUsername; }
    public void setNormalizedUsername(String normalizedUsername) {
        this.normalizedUsername = normalizedUsername;
    }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public HashAlgorithm getHashAlgorithm() { return hashAlgorithm; }
    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public AccountStatus getStatus() { return status; }
    public void setStatus(AccountStatus status) { this.status = status; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    // === 2FA Methods ===

    /**
     * Get all enabled 2FA methods for this account.
     */
    public Set<TwoFactorMethod> getEnabledTwoFactorMethods() {
        return enabledTwoFactorMethods;
    }

    /**
     * Set the enabled 2FA methods for this account.
     */
    public void setEnabledTwoFactorMethods(Set<TwoFactorMethod> methods) {
        this.enabledTwoFactorMethods = methods != null ? methods : EnumSet.noneOf(TwoFactorMethod.class);
    }

    /**
     * Check if a specific 2FA method is enabled.
     */
    public boolean isTwoFactorMethodEnabled(TwoFactorMethod method) {
        return enabledTwoFactorMethods.contains(method);
    }

    /**
     * Enable a specific 2FA method.
     */
    public void enableTwoFactorMethod(TwoFactorMethod method) {
        enabledTwoFactorMethods.add(method);
    }

    /**
     * Disable a specific 2FA method.
     */
    public void disableTwoFactorMethod(TwoFactorMethod method) {
        enabledTwoFactorMethods.remove(method);
    }

    /**
     * Check if any 2FA method is enabled.
     */
    public boolean isTwoFactorEnabled() {
        return !enabledTwoFactorMethods.isEmpty();
    }

    /**
     * Get the primary (first) 2FA method for backwards compatibility.
     * Returns NONE if no methods are enabled.
     */
    public TwoFactorMethod getTwoFactorMethod() {
        if (enabledTwoFactorMethods.isEmpty()) {
            return TwoFactorMethod.NONE;
        }
        // Prefer TOTP as primary, then Telegram, then others
        if (enabledTwoFactorMethods.contains(TwoFactorMethod.TOTP)) {
            return TwoFactorMethod.TOTP;
        }
        if (enabledTwoFactorMethods.contains(TwoFactorMethod.TELEGRAM)) {
            return TwoFactorMethod.TELEGRAM;
        }
        if (enabledTwoFactorMethods.contains(TwoFactorMethod.VK)) {
            return TwoFactorMethod.VK;
        }
        if (enabledTwoFactorMethods.contains(TwoFactorMethod.EMAIL)) {
            return TwoFactorMethod.EMAIL;
        }
        return enabledTwoFactorMethods.iterator().next();
    }

    /**
     * Set a single 2FA method (for backwards compatibility).
     * This will replace all enabled methods with just this one.
     */
    public void setTwoFactorMethod(TwoFactorMethod method) {
        enabledTwoFactorMethods.clear();
        if (method != null && method != TwoFactorMethod.NONE) {
            enabledTwoFactorMethods.add(method);
        }
    }

    // === TOTP ===

    public String getTotpSecret() { return totpSecret; }
    public void setTotpSecret(String secret) { this.totpSecret = secret; }

    /**
     * Get TOTP secret (alias for backwards compatibility).
     */
    public String getTwoFactorSecret() {
        return totpSecret;
    }

    /**
     * Set TOTP secret (alias for backwards compatibility).
     */
    public void setTwoFactorSecret(String secret) {
        this.totpSecret = secret;
    }

    // === Telegram ===

    public String getTelegramChatId() { return telegramChatId; }
    public void setTelegramChatId(String telegramChatId) {
        this.telegramChatId = telegramChatId;
    }

    // === VK ===

    public String getVkUserId() { return vkUserId; }
    public void setVkUserId(String vkUserId) { this.vkUserId = vkUserId; }

    // === Email for 2FA ===

    public String getEmailVerificationCode() { return emailVerificationCode; }
    public void setEmailVerificationCode(String code) {
        this.emailVerificationCode = code;
    }

    // === Security ===

    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public void setFailedLoginAttempts(int attempts) {
        this.failedLoginAttempts = attempts;
    }

    public void incrementFailedAttempts() { this.failedLoginAttempts++; }
    public void resetFailedAttempts() { this.failedLoginAttempts = 0; }

    public Instant getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(Instant lockedUntil) { this.lockedUntil = lockedUntil; }

    public boolean isLocked() {
        return lockedUntil != null && Instant.now().isBefore(lockedUntil);
    }

    public String getRegistrationIp() { return registrationIp; }
    public void setRegistrationIp(String ip) { this.registrationIp = ip; }

    public String getLastLoginIp() { return lastLoginIp; }
    public void setLastLoginIp(String ip) { this.lastLoginIp = ip; }

    public Instant getLastLoginDate() { return lastLoginDate; }
    public void setLastLoginDate(Instant date) { this.lastLoginDate = date; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }

    public boolean isRegistered() {
        return status != AccountStatus.PENDING_REGISTRATION
            && passwordHash != null;
    }

    /**
     * Get the secret/identifier for a specific 2FA method.
     */
    public String getTwoFactorSecretForMethod(TwoFactorMethod method) {
        return switch (method) {
            case TOTP -> totpSecret;
            case TELEGRAM -> telegramChatId;
            case VK -> vkUserId;
            case EMAIL -> email;
            default -> null;
        };
    }

    /**
     * Set the secret/identifier for a specific 2FA method.
     */
    public void setTwoFactorSecretForMethod(TwoFactorMethod method, String value) {
        switch (method) {
            case TOTP -> totpSecret = value;
            case TELEGRAM -> telegramChatId = value;
            case VK -> vkUserId = value;
            default -> {}
        }
    }

    /**
     * Clear all 2FA data for a specific method.
     */
    public void clearTwoFactorMethod(TwoFactorMethod method) {
        enabledTwoFactorMethods.remove(method);
        switch (method) {
            case TOTP -> totpSecret = null;
            case TELEGRAM -> telegramChatId = null;
            case VK -> vkUserId = null;
            case EMAIL -> emailVerificationCode = null;
            default -> {}
        }
    }

    /**
     * Clear all 2FA data for all methods.
     */
    public void clearAllTwoFactorMethods() {
        enabledTwoFactorMethods.clear();
        totpSecret = null;
        telegramChatId = null;
        vkUserId = null;
        emailVerificationCode = null;
    }
}
