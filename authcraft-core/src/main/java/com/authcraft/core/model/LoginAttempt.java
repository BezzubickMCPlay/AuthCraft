// com/authcraft/core/model/LoginAttempt.java
package com.authcraft.core.model;

import java.time.Instant;
import java.util.UUID;

public class LoginAttempt {

    private long id;
    private UUID playerUuid;
    private String ipAddress;
    private boolean success;
    private String failureReason;
    private Instant timestamp;

    public LoginAttempt() {
        this.timestamp = Instant.now();
    }

    public LoginAttempt(UUID playerUuid, String ip, boolean success, String reason) {
        this.playerUuid = playerUuid;
        this.ipAddress = ip;
        this.success = success;
        this.failureReason = reason;
        this.timestamp = Instant.now();
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public UUID getPlayerUuid() { return playerUuid; }
    public void setPlayerUuid(UUID uuid) { this.playerUuid = uuid; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ip) { this.ipAddress = ip; }

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String reason) { this.failureReason = reason; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
}