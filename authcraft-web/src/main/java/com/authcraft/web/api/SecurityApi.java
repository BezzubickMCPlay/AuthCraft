package com.authcraft.web.api;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.web.ApiResponse;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Security API endpoints.
 * Provides security event monitoring and threat management.
 */
public class SecurityApi {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityApi.class);
    
    private final AuthCraftCore core;
    
    public SecurityApi(AuthCraftCore core) {
        this.core = core;
    }
    
    /**
     * Get security events with pagination.
     */
    public void getSecurityEvents(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Pagination
            int page = Integer.parseInt(ctx.queryParam("page") != null ? ctx.queryParam("page") : "1");
            int limit = Integer.parseInt(ctx.queryParam("limit") != null ? ctx.queryParam("limit") : "50");
            String type = ctx.queryParam("type");
            long since = Long.parseLong(ctx.queryParam("since") != null ? ctx.queryParam("since") : "0");
            
            int offset = (page - 1) * limit;
            
            // Get audit events
            List<AuditEvent> events = storage.getAuditEventsSince(since).join();
            
            // Filter by type
            if (type != null && !type.isEmpty()) {
                AuditEventType eventType = AuditEventType.valueOf(type.toUpperCase());
                events = events.stream()
                    .filter(e -> e.getEventType() == eventType)
                    .toList();
            }
            
            // Sort by timestamp descending
            events = events.stream()
                .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
                .toList();
            
            // Paginate
            int total = events.size();
            int totalPages = (int) Math.ceil((double) total / limit);
            events = events.stream()
                .skip(offset)
                .limit(limit)
                .toList();
            
            // Convert to response format
            List<Map<String, Object>> eventList = new ArrayList<>();
            for (AuditEvent event : events) {
                eventList.add(eventToMap(event));
            }
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("page", page);
            result.put("limit", limit);
            result.put("total", total);
            result.put("totalPages", totalPages);
            result.put("events", eventList);
            
            ctx.json(ApiResponse.success("Security events", result));
            
        } catch (Exception e) {
            logger.error("Error getting security events", e);
            ctx.status(500).json(ApiResponse.error("Failed to get security events"));
        }
    }
    
    /**
     * Get active threats.
     */
    public void getActiveThreats(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Get recent failed login attempts (potential attacks)
            long oneHourAgo = System.currentTimeMillis() - 60 * 60 * 1000;
            List<Map<String, Object>> recentFailures = storage.getFailedLoginsSince(oneHourAgo).join();
            
            // Group by IP
            Map<String, Integer> ipFailures = new HashMap<>();
            for (Map<String, Object> failure : recentFailures) {
                String ip = (String) failure.get("ip");
                ipFailures.merge(ip, ((Number) failure.get("count")).intValue(), Integer::sum);
            }
            
            // Find suspicious IPs (more than 10 failures)
            List<Map<String, Object>> threats = new ArrayList<>();
            for (Map.Entry<String, Integer> entry : ipFailures.entrySet()) {
                if (entry.getValue() > 10) {
                    Map<String, Object> threat = new LinkedHashMap<>();
                    threat.put("ip", entry.getKey());
                    threat.put("failedAttempts", entry.getValue());
                    threat.put("severity", entry.getValue() > 50 ? "high" : entry.getValue() > 25 ? "medium" : "low");
                    threat.put("firstSeen", oneHourAgo);
                    threats.add(threat);
                }
            }
            
            // Sort by severity
            threats.sort((a, b) -> {
                int severityOrder = Map.of("high", 3, "medium", 2, "low", 1).get(a.get("severity")) -
                                    Map.of("high", 3, "medium", 2, "low", 1).get(b.get("severity"));
                return severityOrder;
            });
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("total", threats.size());
            result.put("threats", threats);
            
            ctx.json(ApiResponse.success("Active threats", result));
            
        } catch (Exception e) {
            logger.error("Error getting active threats", e);
            ctx.status(500).json(ApiResponse.error("Failed to get active threats"));
        }
    }
    
    /**
     * Get blocked IPs.
     */
    public void getBlockedIps(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Get locked accounts with their IPs
            List<Map<String, Object>> blockedIps = new ArrayList<>();
            
            List<Map<String, Object>> lockedAccounts = storage.getLockedAccountsInfo().join();
            for (Map<String, Object> info : lockedAccounts) {
                Map<String, Object> blocked = new LinkedHashMap<>();
                blocked.put("ip", info.get("lastIp"));
                blocked.put("username", info.get("username"));
                blocked.put("lockedAt", info.get("lockUntil"));
                blocked.put("reason", "Too many failed login attempts");
                blockedIps.add(blocked);
            }
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("total", blockedIps.size());
            result.put("blocked", blockedIps);
            
            ctx.json(ApiResponse.success("Blocked IPs", result));
            
        } catch (Exception e) {
            logger.error("Error getting blocked IPs", e);
            ctx.status(500).json(ApiResponse.error("Failed to get blocked IPs"));
        }
    }
    
    /**
     * Unblock an IP.
     */
    public void unblockIp(Context ctx) {
        try {
            String ip = ctx.pathParam("ip");
            
            StorageProvider storage = core.getStorage();
            
            // Find and unlock accounts associated with this IP
            List<Map<String, Object>> lockedAccounts = storage.getLockedAccountsInfo().join();
            int unlocked = 0;
            
            for (Map<String, Object> info : lockedAccounts) {
                if (ip.equals(info.get("lastIp"))) {
                    // Unlock the account
                    java.util.UUID uuid = (java.util.UUID) info.get("uuid");
                    storage.getAccount(uuid).join().ifPresent(account -> {
                        account.setLockedUntil(null);
                        account.setFailedLoginAttempts(0);
                        storage.saveAccount(account).join();
                    });
                    unlocked++;
                }
            }
            
            logger.info("IP unblocked: {} by {} ({} accounts unlocked)", ip, ctx.attribute("username"), unlocked);
            
            ctx.json(ApiResponse.success("IP unblocked", Map.of("unlockedAccounts", unlocked)));
            
        } catch (Exception e) {
            logger.error("Error unblocking IP", e);
            ctx.status(500).json(ApiResponse.error("Failed to unblock IP"));
        }
    }
    
    /**
     * Get audit log.
     */
    public void getAuditLog(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Pagination
            int page = Integer.parseInt(ctx.queryParam("page") != null ? ctx.queryParam("page") : "1");
            int limit = Integer.parseInt(ctx.queryParam("limit") != null ? ctx.queryParam("limit") : "100");
            String playerUuid = ctx.queryParam("player");
            String action = ctx.queryParam("action");
            
            int offset = (page - 1) * limit;
            
            // Get audit events
            List<AuditEvent> events;
            if (playerUuid != null) {
                events = storage.getAuditEventsForPlayer(java.util.UUID.fromString(playerUuid)).join();
            } else {
                events = storage.getAllAuditEvents().join();
            }
            
            // Filter by action type
            if (action != null && !action.isEmpty()) {
                AuditEventType eventType = AuditEventType.valueOf(action.toUpperCase());
                events = events.stream()
                    .filter(e -> e.getEventType() == eventType)
                    .toList();
            }
            
            // Sort by timestamp descending
            events = events.stream()
                .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
                .toList();
            
            // Paginate
            int total = events.size();
            int totalPages = (int) Math.ceil((double) total / limit);
            events = events.stream()
                .skip(offset)
                .limit(limit)
                .toList();
            
            // Convert to response format
            List<Map<String, Object>> eventList = new ArrayList<>();
            for (AuditEvent event : events) {
                eventList.add(eventToMap(event));
            }
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("page", page);
            result.put("limit", limit);
            result.put("total", total);
            result.put("totalPages", totalPages);
            result.put("events", eventList);
            
            ctx.json(ApiResponse.success("Audit log", result));
            
        } catch (Exception e) {
            logger.error("Error getting audit log", e);
            ctx.status(500).json(ApiResponse.error("Failed to get audit log"));
        }
    }
    
    /**
     * Convert audit event to map for JSON response.
     */
    private Map<String, Object> eventToMap(AuditEvent event) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", event.getId());
        map.put("type", event.getEventType().name());
        map.put("playerUuid", event.getPlayerUuid() != null ? event.getPlayerUuid().toString() : null);
        map.put("playerName", event.getUsername());
        map.put("ip", event.getIpAddress());
        map.put("details", event.getDetails());
        map.put("timestamp", event.getTimestamp().toEpochMilli());
        return map;
    }
}
