// com/authcraft/core/model/AuditEvent.java
package com.authcraft.core.model;

import java.time.Instant;
import java.util.UUID;

public class AuditEvent {

    private long id;
    private AuditEventType eventType;
    private UUID playerUuid;
    private String username;
    private String ipAddress;
    private String details;
    private Instant timestamp;

    public AuditEvent() {
        this.timestamp = Instant.now();
    }

    public static AuditEvent of(AuditEventType type, UUID uuid,
                                String username, String ip, String details) {
        AuditEvent event = new AuditEvent();
        event.eventType = type;
        event.playerUuid = uuid;
        event.username = username;
        event.ipAddress = ip;
        event.details = details;
        return event;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public AuditEventType getEventType() { return eventType; }
    public void setEventType(AuditEventType type) { this.eventType = type; }

    public UUID getPlayerUuid() { return playerUuid; }
    public void setPlayerUuid(UUID uuid) { this.playerUuid = uuid; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ip) { this.ipAddress = ip; }

    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
}