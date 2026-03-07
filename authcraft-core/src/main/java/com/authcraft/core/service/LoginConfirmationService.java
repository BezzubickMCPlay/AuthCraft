// com/authcraft/core/service/LoginConfirmationService.java
package com.authcraft.core.service;

import com.authcraft.core.model.LoginConfirmation;
import com.authcraft.core.model.TwoFactorMethod;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages pending login confirmations (Telegram/VK approve/deny).
 */
public class LoginConfirmationService {

    // confirmationId -> LoginConfirmation
    private final Map<String, LoginConfirmation> pendingConfirmations;
    // playerUuid -> confirmationId
    private final Map<UUID, String> playerConfirmations;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long DEFAULT_TIMEOUT_SECONDS = 120; // 2 minutes

    public LoginConfirmationService() {
        this.pendingConfirmations = new ConcurrentHashMap<>();
        this.playerConfirmations = new ConcurrentHashMap<>();
    }

    /**
     * Create a new login confirmation request.
     */
    public LoginConfirmation createConfirmation(UUID playerUuid, String username,
                                                String ip, String location,
                                                TwoFactorMethod method) {
        // Cancel any existing confirmation for this player
        cancelForPlayer(playerUuid);

        String confirmationId = generateId();

        LoginConfirmation confirmation = new LoginConfirmation(
                confirmationId, playerUuid, username, ip,
                location, method, DEFAULT_TIMEOUT_SECONDS
        );

        pendingConfirmations.put(confirmationId, confirmation);
        playerConfirmations.put(playerUuid, confirmationId);

        return confirmation;
    }

    /**
     * Approve a login confirmation.
     */
    public LoginConfirmation approve(String confirmationId) {
        LoginConfirmation conf = pendingConfirmations.get(confirmationId);
        if (conf == null || !conf.isPending()) return null;

        conf.setStatus(LoginConfirmation.Status.APPROVED);
        cleanup(confirmationId, conf.getPlayerUuid());
        return conf;
    }

    /**
     * Deny a login confirmation.
     */
    public LoginConfirmation deny(String confirmationId) {
        LoginConfirmation conf = pendingConfirmations.get(confirmationId);
        if (conf == null || !conf.isPending()) return null;

        conf.setStatus(LoginConfirmation.Status.DENIED);
        cleanup(confirmationId, conf.getPlayerUuid());
        return conf;
    }

    /**
     * Get confirmation by player UUID.
     */
    public LoginConfirmation getByPlayer(UUID playerUuid) {
        String confId = playerConfirmations.get(playerUuid);
        if (confId == null) return null;
        LoginConfirmation conf = pendingConfirmations.get(confId);
        if (conf != null && conf.isExpired()) {
            conf.setStatus(LoginConfirmation.Status.EXPIRED);
            cleanup(confId, playerUuid);
            return null;
        }
        return conf;
    }

    /**
     * Get confirmation by ID.
     */
    public LoginConfirmation getById(String confirmationId) {
        return pendingConfirmations.get(confirmationId);
    }

    /**
     * Cancel confirmation for a player.
     */
    public void cancelForPlayer(UUID playerUuid) {
        String confId = playerConfirmations.remove(playerUuid);
        if (confId != null) {
            LoginConfirmation conf = pendingConfirmations.remove(confId);
            if (conf != null) {
                conf.setStatus(LoginConfirmation.Status.EXPIRED);
            }
        }
    }

    private void cleanup(String confId, UUID playerUuid) {
        pendingConfirmations.remove(confId);
        playerConfirmations.remove(playerUuid);
    }

    /**
     * Clean up expired confirmations.
     */
    public void cleanupExpired() {
        pendingConfirmations.entrySet().removeIf(entry -> {
            if (entry.getValue().isExpired()) {
                playerConfirmations.remove(entry.getValue().getPlayerUuid());
                return true;
            }
            return false;
        });
    }

    private String generateId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}