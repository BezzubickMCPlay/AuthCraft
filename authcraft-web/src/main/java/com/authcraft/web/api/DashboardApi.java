package com.authcraft.web.api;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.Account;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.web.ApiResponse;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Dashboard API endpoints.
 * Provides statistics, online players, and activity data.
 */
public class DashboardApi {
    
    private static final Logger logger = LoggerFactory.getLogger(DashboardApi.class);
    
    private final AuthCraftCore core;
    
    public DashboardApi(AuthCraftCore core) {
        this.core = core;
    }
    
    /**
     * Get dashboard statistics.
     */
    public void getStats(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Get counts
            long totalAccounts = storage.countAllAccounts().join();
            long activeSessions = storage.countActiveSessions().join();
            long lockedAccounts = storage.countLockedAccounts().join();
            long twoFactorEnabled = storage.countTwoFactorEnabled().join();
            
            // Get online players
            int onlinePlayers = core.getAuthenticatedPlayers().size();
            
            // Get recent activity (last 24 hours)
            long logins24h = storage.countLoginsSince(System.currentTimeMillis() - 24 * 60 * 60 * 1000).join();
            long registrations24h = storage.countRegistrationsSince(System.currentTimeMillis() - 24 * 60 * 60 * 1000).join();
            long failedLogins24h = storage.countFailedLoginsSince(System.currentTimeMillis() - 24 * 60 * 60 * 1000).join();
            
            Map<String, Object> stats = new LinkedHashMap<>();
            
            // Player stats
            Map<String, Object> players = new LinkedHashMap<>();
            players.put("online", onlinePlayers);
            players.put("total", totalAccounts);
            players.put("locked", lockedAccounts);
            stats.put("players", players);
            
            // Session stats
            Map<String, Object> sessions = new LinkedHashMap<>();
            sessions.put("active", activeSessions);
            stats.put("sessions", sessions);
            
            // 2FA stats
            Map<String, Object> twoFactor = new LinkedHashMap<>();
            twoFactor.put("enabled", twoFactorEnabled);
            twoFactor.put("adoptionRate", totalAccounts > 0 ? (double) twoFactorEnabled / totalAccounts * 100 : 0);
            stats.put("twoFactor", twoFactor);
            
            // Activity stats (24h)
            Map<String, Object> activity = new LinkedHashMap<>();
            activity.put("logins", logins24h);
            activity.put("registrations", registrations24h);
            activity.put("failedLogins", failedLogins24h);
            stats.put("activity24h", activity);
            
            // Server info
            Map<String, Object> server = new LinkedHashMap<>();
            server.put("version", "1.0.0");
            server.put("uptime", System.currentTimeMillis());
            stats.put("server", server);
            
            ctx.json(ApiResponse.success("Dashboard statistics", stats));
            
        } catch (Exception e) {
            logger.error("Error getting dashboard stats", e);
            ctx.status(500).json(ApiResponse.error("Failed to get statistics"));
        }
    }
    
    /**
     * Get online players list.
     */
    public void getOnlinePlayers(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            Set<java.util.UUID> authenticated = core.getAuthenticatedPlayers();
            
            List<Map<String, Object>> players = new ArrayList<>();
            
            for (java.util.UUID uuid : authenticated) {
                storage.getAccount(uuid).join().ifPresent(account -> {
                    Map<String, Object> player = new LinkedHashMap<>();
                    player.put("uuid", account.getUuid().toString());
                    player.put("username", account.getUsername());
                    player.put("role", account.getRole() != null ? account.getRole() : "player");
                    player.put("twoFactorEnabled", !account.getEnabledTwoFactorMethods().isEmpty());
                    player.put("lastLogin", account.getLastLoginDate() != null ? account.getLastLoginDate().toEpochMilli() : null);
                    players.add(player);
                });
            }
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("count", players.size());
            result.put("players", players);
            
            ctx.json(ApiResponse.success("Online players", result));
            
        } catch (Exception e) {
            logger.error("Error getting online players", e);
            ctx.status(500).json(ApiResponse.error("Failed to get online players"));
        }
    }
    
    /**
     * Get activity timeline.
     */
    public void getActivity(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Get time range from query params (default: 24 hours)
            long endTime = System.currentTimeMillis();
            long startTime = endTime - 24 * 60 * 60 * 1000;
            
            String range = ctx.queryParam("range");
            if (range != null) {
                switch (range.toLowerCase()) {
                    case "1h" -> startTime = endTime - 60 * 60 * 1000;
                    case "7d" -> startTime = endTime - 7 * 24 * 60 * 60 * 1000;
                    case "30d" -> startTime = endTime - 30L * 24 * 60 * 60 * 1000;
                }
            }
            
            // Get login attempts for the period
            List<Map<String, Object>> events = storage.getLoginAttemptsBetween(startTime, endTime).join();
            
            // Group by hour
            Map<String, Map<String, Integer>> hourlyStats = new LinkedHashMap<>();
            
            for (Map<String, Object> event : events) {
                long timestamp = ((Number) event.get("timestamp")).longValue();
                boolean success = (Boolean) event.get("success");
                
                // Get hour bucket
                java.time.Instant instant = java.time.Instant.ofEpochMilli(timestamp);
                String hourKey = instant.toString().substring(0, 13); // YYYY-MM-DDTHH
                
                hourlyStats.computeIfAbsent(hourKey, k -> {
                    Map<String, Integer> counts = new LinkedHashMap<>();
                    counts.put("logins", 0);
                    counts.put("failures", 0);
                    return counts;
                });
                
                if (success) {
                    hourlyStats.get(hourKey).merge("logins", 1, Integer::sum);
                } else {
                    hourlyStats.get(hourKey).merge("failures", 1, Integer::sum);
                }
            }
            
            // Convert to list for response
            List<Map<String, Object>> timeline = new ArrayList<>();
            for (Map.Entry<String, Map<String, Integer>> entry : hourlyStats.entrySet()) {
                Map<String, Object> point = new LinkedHashMap<>();
                point.put("time", entry.getKey());
                point.put("logins", entry.getValue().get("logins"));
                point.put("failures", entry.getValue().get("failures"));
                timeline.add(point);
            }
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("range", range != null ? range : "24h");
            result.put("timeline", timeline);
            
            ctx.json(ApiResponse.success("Activity timeline", result));
            
        } catch (Exception e) {
            logger.error("Error getting activity", e);
            ctx.status(500).json(ApiResponse.error("Failed to get activity"));
        }
    }
}
