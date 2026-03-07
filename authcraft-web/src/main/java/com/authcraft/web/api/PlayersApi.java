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
 * Players API endpoints.
 * Provides player management functionality.
 */
public class PlayersApi {
    
    private static final Logger logger = LoggerFactory.getLogger(PlayersApi.class);
    
    private final AuthCraftCore core;
    
    public PlayersApi(AuthCraftCore core) {
        this.core = core;
    }
    
    /**
     * List all players with pagination.
     */
    public void listPlayers(Context ctx) {
        try {
            StorageProvider storage = core.getStorage();
            
            // Pagination
            int page = Integer.parseInt(ctx.queryParam("page") != null ? ctx.queryParam("page") : "1");
            int limit = Integer.parseInt(ctx.queryParam("limit") != null ? ctx.queryParam("limit") : "50");
            String search = ctx.queryParam("search");
            String sortBy = ctx.queryParam("sortBy") != null ? ctx.queryParam("sortBy") : "username";
            
            int offset = (page - 1) * limit;
            
            // Get accounts
            List<Account> accounts = storage.getAllAccounts().join();
            
            // Filter by search
            if (search != null && !search.isEmpty()) {
                String searchLower = search.toLowerCase();
                accounts = accounts.stream()
                    .filter(a -> a.getUsername().toLowerCase().contains(searchLower))
                    .toList();
            }
            
            // Sort
            accounts = accounts.stream()
                .sorted((a, b) -> {
                    switch (sortBy) {
                        case "lastLogin" -> {
                            long aTime = a.getLastLoginDate() != null ? a.getLastLoginDate().toEpochMilli() : 0;
                            long bTime = b.getLastLoginDate() != null ? b.getLastLoginDate().toEpochMilli() : 0;
                            return Long.compare(bTime, aTime); // Descending
                        }
                        case "username" -> {
                            return a.getUsername().compareToIgnoreCase(b.getUsername());
                        }
                        default -> {
                            return a.getUsername().compareToIgnoreCase(b.getUsername());
                        }
                    }
                })
                .toList();
            
            // Paginate
            int total = accounts.size();
            int totalPages = (int) Math.ceil((double) total / limit);
            accounts = accounts.stream()
                .skip(offset)
                .limit(limit)
                .toList();
            
            // Convert to response format
            List<Map<String, Object>> players = new ArrayList<>();
            for (Account account : accounts) {
                players.add(accountToMap(account));
            }
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("page", page);
            result.put("limit", limit);
            result.put("total", total);
            result.put("totalPages", totalPages);
            result.put("players", players);
            
            ctx.json(ApiResponse.success("Players list", result));
            
        } catch (Exception e) {
            logger.error("Error listing players", e);
            ctx.status(500).json(ApiResponse.error("Failed to list players"));
        }
    }
    
    /**
     * Get a specific player by UUID.
     */
    public void getPlayer(Context ctx) {
        try {
            String uuidStr = ctx.pathParam("uuid");
            java.util.UUID uuid = java.util.UUID.fromString(uuidStr);
            
            StorageProvider storage = core.getStorage();
            Optional<Account> optAccount = storage.getAccount(uuid).join();
            
            if (optAccount.isEmpty()) {
                ctx.status(404).json(ApiResponse.error("Player not found"));
                return;
            }
            
            Account account = optAccount.get();
            Map<String, Object> playerData = accountToMap(account);
            
            // Add additional details
            playerData.put("sessions", storage.getSessionsForPlayer(uuid).join().size());
            playerData.put("loginAttempts", storage.getLoginAttemptsForPlayer(uuid).join().size());
            
            ctx.json(ApiResponse.success("Player details", playerData));
            
        } catch (IllegalArgumentException e) {
            ctx.status(400).json(ApiResponse.error("Invalid UUID format"));
        } catch (Exception e) {
            logger.error("Error getting player", e);
            ctx.status(500).json(ApiResponse.error("Failed to get player"));
        }
    }
    
    /**
     * Update a player's account.
     */
    public void updatePlayer(Context ctx) {
        try {
            String uuidStr = ctx.pathParam("uuid");
            java.util.UUID uuid = java.util.UUID.fromString(uuidStr);
            
            StorageProvider storage = core.getStorage();
            Optional<Account> optAccount = storage.getAccount(uuid).join();
            
            if (optAccount.isEmpty()) {
                ctx.status(404).json(ApiResponse.error("Player not found"));
                return;
            }
            
            Account account = optAccount.get();
            UpdateRequest request = ctx.bodyAsClass(UpdateRequest.class);
            
            // Update fields if provided
            if (request.role != null) {
                account.setRole(request.role);
                logger.info("Role update requested for {}: {}", account.getUsername(), request.role);
            }
            
            storage.saveAccount(account).join();
            
            ctx.json(ApiResponse.success("Player updated", accountToMap(account)));
            
        } catch (IllegalArgumentException e) {
            ctx.status(400).json(ApiResponse.error("Invalid UUID format"));
        } catch (Exception e) {
            logger.error("Error updating player", e);
            ctx.status(500).json(ApiResponse.error("Failed to update player"));
        }
    }
    
    /**
     * Delete a player's account.
     */
    public void deletePlayer(Context ctx) {
        try {
            String uuidStr = ctx.pathParam("uuid");
            java.util.UUID uuid = java.util.UUID.fromString(uuidStr);
            
            StorageProvider storage = core.getStorage();
            Optional<Account> optAccount = storage.getAccount(uuid).join();
            
            if (optAccount.isEmpty()) {
                ctx.status(404).json(ApiResponse.error("Player not found"));
                return;
            }
            
            Account account = optAccount.get();
            
            // Delete account
            storage.deleteAccount(uuid).join();
            
            logger.info("Account deleted: {} by {}", account.getUsername(), ctx.attribute("username"));
            
            ctx.json(ApiResponse.success("Account deleted"));
            
        } catch (IllegalArgumentException e) {
            ctx.status(400).json(ApiResponse.error("Invalid UUID format"));
        } catch (Exception e) {
            logger.error("Error deleting player", e);
            ctx.status(500).json(ApiResponse.error("Failed to delete player"));
        }
    }
    
    /**
     * Unlock a locked player account.
     */
    public void unlockPlayer(Context ctx) {
        try {
            String uuidStr = ctx.pathParam("uuid");
            java.util.UUID uuid = java.util.UUID.fromString(uuidStr);
            
            StorageProvider storage = core.getStorage();
            Optional<Account> optAccount = storage.getAccount(uuid).join();
            
            if (optAccount.isEmpty()) {
                ctx.status(404).json(ApiResponse.error("Player not found"));
                return;
            }
            
            Account account = optAccount.get();
            
            if (!account.isLocked()) {
                ctx.json(ApiResponse.success("Account is not locked"));
                return;
            }
            
            // Unlock account
            account.setLockedUntil(null);
            account.setFailedLoginAttempts(0);
            
            storage.saveAccount(account).join();
            
            logger.info("Account unlocked: {} by {}", account.getUsername(), ctx.attribute("username"));
            
            ctx.json(ApiResponse.success("Account unlocked", accountToMap(account)));
            
        } catch (IllegalArgumentException e) {
            ctx.status(400).json(ApiResponse.error("Invalid UUID format"));
        } catch (Exception e) {
            logger.error("Error unlocking player", e);
            ctx.status(500).json(ApiResponse.error("Failed to unlock player"));
        }
    }
    
    /**
     * Reset 2FA for a player.
     */
    public void reset2FA(Context ctx) {
        try {
            String uuidStr = ctx.pathParam("uuid");
            java.util.UUID uuid = java.util.UUID.fromString(uuidStr);
            
            StorageProvider storage = core.getStorage();
            Optional<Account> optAccount = storage.getAccount(uuid).join();
            
            if (optAccount.isEmpty()) {
                ctx.status(404).json(ApiResponse.error("Player not found"));
                return;
            }
            
            Account account = optAccount.get();
            
            // Reset 2FA
            account.setTwoFactorMethod(null);
            account.getEnabledTwoFactorMethods().clear();
            
            storage.saveAccount(account).join();
            storage.deleteBackupCodes(uuid).join();
            
            logger.info("2FA reset for: {} by {}", account.getUsername(), ctx.attribute("username"));
            
            ctx.json(ApiResponse.success("2FA reset successfully", accountToMap(account)));
            
        } catch (IllegalArgumentException e) {
            ctx.status(400).json(ApiResponse.error("Invalid UUID format"));
        } catch (Exception e) {
            logger.error("Error resetting 2FA", e);
            ctx.status(500).json(ApiResponse.error("Failed to reset 2FA"));
        }
    }
    
    /**
     * Convert account to map for JSON response.
     */
    private Map<String, Object> accountToMap(Account account) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("uuid", account.getUuid().toString());
        map.put("username", account.getUsername());
        map.put("role", account.getRole() != null ? account.getRole() : "player");
        map.put("registered", account.getCreatedAt() != null ? account.getCreatedAt().toEpochMilli() : null);
        map.put("lastLogin", account.getLastLoginDate() != null ? account.getLastLoginDate().toEpochMilli() : null);
        map.put("lastIp", account.getLastLoginIp());
        map.put("locked", account.isLocked());
        map.put("failedAttempts", account.getFailedLoginAttempts());
        map.put("twoFactorEnabled", !account.getEnabledTwoFactorMethods().isEmpty());
        map.put("twoFactorMethods", account.getEnabledTwoFactorMethods().stream().map(Enum::name).toList());
        return map;
    }
    
    // Request DTOs
    
    public static class UpdateRequest {
        public String role;
        public Boolean locked;
    }
}
