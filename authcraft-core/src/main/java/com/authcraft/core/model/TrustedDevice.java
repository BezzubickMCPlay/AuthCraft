// com/authcraft/core/model/TrustedDevice.java
package com.authcraft.core.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a trusted device for "Remember this device" functionality.
 * Allows players to skip 2FA on recognized devices.
 */
public class TrustedDevice {

    private final UUID playerUuid;
    private final String tokenHash;
    private final String deviceName;
    private final String ipAddress;
    private final Instant createdAt;
    private final Instant expiresAt;
    private Instant lastUsedAt;

    public TrustedDevice(UUID playerUuid, String tokenHash, String deviceName, 
                         String ipAddress, Instant expiresAt) {
        this.playerUuid = playerUuid;
        this.tokenHash = tokenHash;
        this.deviceName = deviceName;
        this.ipAddress = ipAddress;
        this.createdAt = Instant.now();
        this.expiresAt = expiresAt;
        this.lastUsedAt = this.createdAt;
    }

    public TrustedDevice(UUID playerUuid, String tokenHash, String deviceName,
                         String ipAddress, Instant createdAt, Instant expiresAt, 
                         Instant lastUsedAt) {
        this.playerUuid = playerUuid;
        this.tokenHash = tokenHash;
        this.deviceName = deviceName;
        this.ipAddress = ipAddress;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.lastUsedAt = lastUsedAt;
    }

    /**
     * Check if this trusted device has expired.
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Update the last used timestamp to now.
     */
    public void updateLastUsed() {
        this.lastUsedAt = Instant.now();
    }

    // Getters

    public UUID getPlayerUuid() {
        return playerUuid;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }
}
