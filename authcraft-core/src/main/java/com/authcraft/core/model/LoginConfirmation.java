// com/authcraft/core/model/LoginConfirmation.java
package com.authcraft.core.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a pending login confirmation request
 * sent via Telegram/VK with approve/deny buttons.
 */
public class LoginConfirmation {

    public enum Status {
        PENDING,
        APPROVED,
        DENIED,
        EXPIRED
    }

    private final String confirmationId;
    private final UUID playerUuid;
    private final String username;
    private final String ipAddress;
    private final String location; // GeoIP resolved
    private final TwoFactorMethod method;
    private final Instant createdAt;
    private final Instant expiresAt;
    private volatile Status status;

    public LoginConfirmation(String confirmationId, UUID playerUuid,
                             String username, String ipAddress,
                             String location, TwoFactorMethod method,
                             long timeoutSeconds) {
        this.confirmationId = confirmationId;
        this.playerUuid = playerUuid;
        this.username = username;
        this.ipAddress = ipAddress;
        this.location = location;
        this.method = method;
        this.createdAt = Instant.now();
        this.expiresAt = createdAt.plusSeconds(timeoutSeconds);
        this.status = Status.PENDING;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt) || status == Status.EXPIRED;
    }

    public boolean isPending() {
        return status == Status.PENDING && !isExpired();
    }

    public String getConfirmationId() { return confirmationId; }
    public UUID getPlayerUuid() { return playerUuid; }
    public String getUsername() { return username; }
    public String getIpAddress() { return ipAddress; }
    public String getLocation() { return location; }
    public TwoFactorMethod getMethod() { return method; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
}