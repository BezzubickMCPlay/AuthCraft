// com/authcraft/core/service/SessionService.java
package com.authcraft.core.service;

import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Session;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Manages player sessions: creation, validation, invalidation.
 */
public class SessionService {

    private final StorageProvider storage;
    private final AuthCraftConfig config;

    public SessionService(StorageProvider storage, AuthCraftConfig config) {
        this.storage = storage;
        this.config = config;
    }

    /**
     * Create a new session for a player.
     */
    public CompletableFuture<Session> createSession(UUID uuid, String ip) {
        // Invalidate old sessions first
        return storage.deleteSession(uuid).thenCompose(v -> {
            Session session = new Session(
                    uuid, ip, config.getSessionTtlHours()
            );
            return storage.saveSession(session)
                    .thenApply(v2 -> session);
        });
    }

    /**
     * Try to restore an existing valid session.
     */
    public CompletableFuture<Optional<Session>> tryRestoreSession(
            UUID uuid, String ip) {
        return storage.getSession(uuid).thenApply(optSession -> {
            if (optSession.isEmpty()) return Optional.empty();

            Session session = optSession.get();

            if (!session.isValid()) {
                // Session expired — clean up async
                storage.deleteSession(uuid);
                return Optional.empty();
            }

            if (config.isSessionStrictIp()
                    && !session.isValidForIp(ip)) {
                // IP mismatch — invalidate
                storage.deleteSession(uuid);
                return Optional.empty();
            }

            return Optional.of(session);
        });
    }

    /**
     * Invalidate all sessions for a player
     * (e.g., on password change).
     */
    public CompletableFuture<Void> invalidateAllSessions(UUID uuid) {
        return storage.invalidateAllSessions(uuid);
    }

    /**
     * Delete a single session.
     */
    public CompletableFuture<Void> deleteSession(UUID uuid) {
        return storage.deleteSession(uuid);
    }

    /**
     * Cleanup expired sessions from database.
     */
    public void cleanupExpiredSessions() {
        storage.deleteExpiredSessions().exceptionally(ex -> {
            // Log but don't crash
            return null;
        });
    }

    /**
     * Mark a session as 2FA-verified.
     */
    public CompletableFuture<Void> markTwoFactorVerified(UUID uuid) {
        return storage.getSession(uuid).thenCompose(optSession -> {
            if (optSession.isPresent()) {
                Session session = optSession.get();
                session.setTwoFactorVerified(true);
                return storage.saveSession(session);
            }
            return CompletableFuture.completedFuture(null);
        });
    }
}