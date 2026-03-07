// com/authcraft/core/model/Session.java
package com.authcraft.core.model;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class Session {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private String token;
    private UUID playerUuid;
    private String ipAddress;
    private Instant createdAt;
    private Instant expiresAt;
    private boolean authenticated;
    private boolean twoFactorVerified;

    public Session() {}

    public Session(UUID playerUuid, String ipAddress, long ttlHours) {
        this.token = generateToken();
        this.playerUuid = playerUuid;
        this.ipAddress = ipAddress;
        this.createdAt = Instant.now();
        this.expiresAt = createdAt.plusSeconds(ttlHours * 3600);
        this.authenticated = true;
        this.twoFactorVerified = false;
    }

    private static String generateToken() {
        byte[] bytes = new byte[48]; // 64 chars base64
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public boolean isValid() {
        return authenticated && Instant.now().isBefore(expiresAt);
    }

    public boolean isValidForIp(String ip) {
        return isValid() && this.ipAddress.equals(ip);
    }

    // === Getters & Setters ===

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public UUID getPlayerUuid() { return playerUuid; }
    public void setPlayerUuid(UUID uuid) { this.playerUuid = uuid; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ip) { this.ipAddress = ip; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public boolean isAuthenticated() { return authenticated; }
    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public boolean isTwoFactorVerified() { return twoFactorVerified; }
    public void setTwoFactorVerified(boolean verified) {
        this.twoFactorVerified = verified;
    }

    public void invalidate() {
        this.authenticated = false;
    }
}