// com/authcraft/core/service/TrustedDeviceService.java
package com.authcraft.core.service;

import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.TrustedDevice;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Manages trusted devices for "Remember this device" functionality.
 * Allows players to skip 2FA on recognized devices.
 */
public class TrustedDeviceService {

    private final StorageProvider storage;
    private final AuthCraftConfig config;
    private final SecureRandom random = new SecureRandom();

    public TrustedDeviceService(StorageProvider storage, AuthCraftConfig config) {
        this.storage = storage;
        this.config = config;
    }

    /**
     * Generate a device token for a trusted device.
     * Returns a token that should be stored client-side (e.g., in a cookie or local storage).
     */
    public CompletableFuture<String> trustDevice(UUID playerUuid, String deviceName, String ipAddress) {
        String token = generateDeviceToken();
        String tokenHash = hashToken(token);
        
        TrustedDevice device = new TrustedDevice(
            playerUuid,
            tokenHash,
            deviceName,
            ipAddress,
            Instant.now().plusSeconds(config.getTrustedDeviceTtlDays() * 24L * 60 * 60)
        );
        
        return storage.saveTrustedDevice(device)
            .thenApply(v -> token);
    }

    /**
     * Validate a device token.
     * Returns the trusted device if valid, empty if not found or expired.
     */
    public CompletableFuture<Optional<TrustedDevice>> validateDevice(UUID playerUuid, String token) {
        if (token == null || token.isEmpty()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        
        String tokenHash = hashToken(token);
        return storage.getTrustedDevice(playerUuid, tokenHash)
            .thenApply(optDevice -> {
                if (optDevice.isEmpty()) {
                    return Optional.empty();
                }
                
                TrustedDevice device = optDevice.get();
                if (device.isExpired()) {
                    // Clean up expired device
                    storage.deleteTrustedDevice(playerUuid, tokenHash);
                    return Optional.empty();
                }
                
                // Update last used timestamp
                device.updateLastUsed();
                storage.saveTrustedDevice(device);
                
                return Optional.of(device);
            });
    }

    /**
     * Revoke a trusted device.
     */
    public CompletableFuture<Void> revokeDevice(UUID playerUuid, String token) {
        String tokenHash = hashToken(token);
        return storage.deleteTrustedDevice(playerUuid, tokenHash);
    }

    /**
     * Revoke all trusted devices for a player.
     */
    public CompletableFuture<Void> revokeAllDevices(UUID playerUuid) {
        return storage.deleteAllTrustedDevices(playerUuid);
    }

    /**
     * Generate a secure random device token.
     */
    private String generateDeviceToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Hash a token for storage.
     * Uses SHA-256 for one-way hashing.
     */
    private String hashToken(String token) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            // SHA-256 is always available
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
