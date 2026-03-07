// com/authcraft/core/api/PlatformAdapter.java
package com.authcraft.core.api;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

/**
 * Adapter to abstract platform-specific operations.
 * Implemented by Bukkit, BungeeCord, Velocity modules.
 */
public interface PlatformAdapter {

    /**
     * Send a message to a player.
     */
    void sendMessage(UUID playerUuid, String message);

    /**
     * Send a title to a player.
     */
    void sendTitle(UUID playerUuid, String title,
                   String subtitle, int fadeIn, int stay, int fadeOut);

    /**
     * Kick a player with a reason.
     */
    void kickPlayer(UUID playerUuid, String reason);

    /**
     * Check if a player is online.
     */
    boolean isPlayerOnline(UUID playerUuid);

    /**
     * Get a player's IP address.
     */
    String getPlayerIp(UUID playerUuid);

    /**
     * Get the player's username.
     */
    String getPlayerName(UUID playerUuid);

    /**
     * Freeze/unfreeze a player (limbo state).
     */
    void setLimboState(UUID playerUuid, boolean limbo);

    /**
     * Give a player a permission.
     */
    void setPermission(UUID playerUuid, String permission, boolean value);

    /**
     * Check if a player has a permission.
     */
    boolean hasPermission(UUID playerUuid, String permission);

    /**
     * Run a task asynchronously.
     */
    void runAsync(Runnable task);

    /**
     * Run a task on the main/server thread.
     */
    void runSync(Runnable task);

    /**
     * Schedule a repeating async task.
     * Returns a task ID for cancellation.
     */
    int scheduleRepeating(Runnable task, long delayTicks, long periodTicks);

    /**
     * Cancel a scheduled task.
     */
    void cancelTask(int taskId);

    /**
     * Get the platform logger.
     */
    Logger getLogger();

    /**
     * Get the platform data folder.
     */
    java.io.File getDataFolder();

    /**
     * Get the server port.
     */
    int getServerPort();

    /**
     * Get all online player UUIDs.
     */
    java.util.Collection<UUID> getOnlinePlayers();

    /**
     * Get a player's locale/language setting.
     * Returns the player's client language code (e.g., "en", "ru", "de").
     */
    String getPlayerLocale(UUID playerUuid);

    /**
     * Broadcast a message to players with a permission.
     */
    void broadcastPermission(String message, String permission);

    /**
     * Resolve a location from an IP address.
     * Returns a string representation of the country/region, or null if unavailable.
     */
    default String resolveLocation(String ipAddress) {
        return null;
    }

    /**
     * Get the server name for identification in multi-server setups.
     * Returns a unique name for this server instance.
     */
    default String getServerName() {
        return "server-" + getServerPort();
    }
}