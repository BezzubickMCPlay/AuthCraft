package com.authcraft.web.api;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.web.ApiResponse;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Two-Factor Authentication API endpoints.
 * Provides 2FA statistics and analytics.
 */
public class TwoFactorApi {
    
    private static final Logger logger = LoggerFactory.getLogger(TwoFactorApi.class);
    
    private final AuthCraftCore core;
    
    public TwoFactorApi(AuthCraftCore core) {
        this.core = core;
    }
    
    /**
     * Get 2FA statistics.
     */
    public void getStats(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Get counts
            long totalAccounts = storage.countAllAccounts().join();
            long twoFactorEnabled = storage.countTwoFactorEnabled().join();
            
            // Get method distribution
            Map<String, Long> methodCounts = new LinkedHashMap<>();
            for (TwoFactorMethod method : TwoFactorMethod.values()) {
                long count = storage.countTwoFactorMethod(method).join();
                methodCounts.put(method.name(), count);
            }
            
            // Calculate adoption rate
            double adoptionRate = totalAccounts > 0 ? (double) twoFactorEnabled / totalAccounts * 100 : 0;
            
            // Get recent 2FA verifications
            long oneDayAgo = System.currentTimeMillis() - 24 * 60 * 60 * 1000;
            long verifications24h = storage.countTwoFactorVerificationsSince(oneDayAgo).join();
            
            Map<String, Object> stats = new LinkedHashMap<>();
            
            // Overview
            Map<String, Object> overview = new LinkedHashMap<>();
            overview.put("totalAccounts", totalAccounts);
            overview.put("twoFactorEnabled", twoFactorEnabled);
            overview.put("twoFactorDisabled", totalAccounts - twoFactorEnabled);
            overview.put("adoptionRate", Math.round(adoptionRate * 100.0) / 100.0);
            stats.put("overview", overview);
            
            // Method distribution
            stats.put("methodDistribution", methodCounts);
            
            // Activity
            Map<String, Object> activity = new LinkedHashMap<>();
            activity.put("verifications24h", verifications24h);
            stats.put("activity", activity);
            
            ctx.json(ApiResponse.success("2FA statistics", stats));
            
        } catch (Exception e) {
            logger.error("Error getting 2FA stats", e);
            ctx.status(500).json(ApiResponse.error("Failed to get 2FA statistics"));
        }
    }
    
    /**
     * Get 2FA method distribution.
     */
    public void getMethodDistribution(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Get counts for each method
            Map<String, Long> distribution = new LinkedHashMap<>();
            long total = 0;
            
            for (TwoFactorMethod method : TwoFactorMethod.values()) {
                long count = storage.countTwoFactorMethod(method).join();
                distribution.put(method.name(), count);
                total += count;
            }
            
            // Calculate percentages
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("total", total);
            
            List<Map<String, Object>> methods = new ArrayList<>();
            for (Map.Entry<String, Long> entry : distribution.entrySet()) {
                Map<String, Object> methodData = new LinkedHashMap<>();
                methodData.put("method", entry.getKey());
                methodData.put("count", entry.getValue());
                methodData.put("percentage", total > 0 ? Math.round((double) entry.getValue() / total * 10000.0) / 100.0 : 0);
                methods.add(methodData);
            }
            result.put("methods", methods);
            
            ctx.json(ApiResponse.success("2FA method distribution", result));
            
        } catch (Exception e) {
            logger.error("Error getting method distribution", e);
            ctx.status(500).json(ApiResponse.error("Failed to get method distribution"));
        }
    }
    
    /**
     * Get 2FA adoption rate over time.
     */
    public void getAdoptionRate(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Get time range from query params (default: 30 days)
            int days = Integer.parseInt(ctx.queryParam("days") != null ? ctx.queryParam("days") : "30");
            long startTime = System.currentTimeMillis() - (long) days * 24 * 60 * 60 * 1000;
            
            // Get registration data grouped by day
            List<Map<String, Object>> registrations = storage.getRegistrationsByDay(startTime).join();
            
            // Get 2FA enable events grouped by day
            List<Map<String, Object>> twoFactorEnables = storage.getTwoFactorEnablesByDay(startTime).join();
            
            // Build timeline
            Map<String, Map<String, Long>> dailyData = new TreeMap<>();
            
            for (Map<String, Object> reg : registrations) {
                String day = (String) reg.get("day");
                long count = ((Number) reg.get("count")).longValue();
                dailyData.computeIfAbsent(day, k -> new LinkedHashMap<>())
                    .put("registrations", count);
            }
            
            for (Map<String, Object> tf : twoFactorEnables) {
                String day = (String) tf.get("day");
                long count = ((Number) tf.get("count")).longValue();
                dailyData.computeIfAbsent(day, k -> new LinkedHashMap<>())
                    .put("twoFactorEnables", count);
            }
            
            // Calculate cumulative adoption rate
            List<Map<String, Object>> timeline = new ArrayList<>();
            long cumulativeTotal = 0;
            long cumulative2FA = 0;
            
            for (Map.Entry<String, Map<String, Long>> entry : dailyData.entrySet()) {
                Map<String, Long> dayData = entry.getValue();
                cumulativeTotal += dayData.getOrDefault("registrations", 0L);
                cumulative2FA += dayData.getOrDefault("twoFactorEnables", 0L);
                
                Map<String, Object> point = new LinkedHashMap<>();
                point.put("date", entry.getKey());
                point.put("totalAccounts", cumulativeTotal);
                point.put("twoFactorEnabled", cumulative2FA);
                point.put("adoptionRate", cumulativeTotal > 0 ? 
                    Math.round((double) cumulative2FA / cumulativeTotal * 10000.0) / 100.0 : 0);
                timeline.add(point);
            }
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("days", days);
            result.put("timeline", timeline);
            
            ctx.json(ApiResponse.success("2FA adoption rate", result));
            
        } catch (Exception e) {
            logger.error("Error getting adoption rate", e);
            ctx.status(500).json(ApiResponse.error("Failed to get adoption rate"));
        }
    }
}
