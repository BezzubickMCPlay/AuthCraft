// com/authcraft/core/service/TwoFactorService.java
package com.authcraft.core.service;

import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.BackupCode;
import com.authcraft.core.model.TwoFactorMethod;

import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Orchestrates 2FA setup, verification, and backup codes.
 */
public class TwoFactorService {

    private final StorageProvider storage;
    private final Map<TwoFactorMethod, TwoFactorProvider> providers;
    private final AuthCraftConfig config;

    public TwoFactorService(
            StorageProvider storage,
            Map<TwoFactorMethod, TwoFactorProvider> providers,
            AuthCraftConfig config) {
        this.storage = storage;
        this.providers = providers;
        this.config = config;
    }

    /**
     * Begin 2FA setup: generate secret and (optionally) QR code.
     */
    public TwoFactorSetupResult beginSetup(
            TwoFactorMethod method, UUID uuid, String username) {
        TwoFactorProvider provider = providers.get(method);
        if (provider == null || !provider.isAvailable()) {
            throw new IllegalArgumentException(
                "2FA method not available: " + method
            );
        }
    
        String secret = provider.generateSecret(uuid, username);
        byte[] qrCode = null;
        String qrCodeUrl = null;
        if (method == TwoFactorMethod.TOTP) {
            qrCode = provider.generateQrCode(secret, username, 200);
            // Generate URL for clickable link
            qrCodeUrl = "otpauth://totp/AuthCraft:" + username +
                "?secret=" + secret + "&issuer=AuthCraft&digits=6&period=30";
        }
    
        return new TwoFactorSetupResult(secret, qrCode, qrCodeUrl, method);
    }

    /**
     * Confirm 2FA setup by verifying a code, then generate backup codes.
     */
    public CompletableFuture<List<String>> confirmSetup(
            UUID uuid, TwoFactorMethod method,
            String secret, String code) {
        TwoFactorProvider provider = providers.get(method);
        if (provider == null) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Unknown 2FA method")
            );
        }

        if (!provider.verifyCode(secret, code)) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Invalid verification code")
            );
        }

        // Generate backup codes
        int count = config.getBackupCodeCount();
        List<String[]> codePairs = BackupCode.generateCodes(uuid, count);

        List<String> plaintextCodes = new ArrayList<>();
        List<BackupCode> backupCodes = new ArrayList<>();

        for (String[] pair : codePairs) {
            plaintextCodes.add(pair[0]);
            backupCodes.add(new BackupCode(uuid, pair[1]));
        }

        // Save backup codes
        return storage.deleteBackupCodes(uuid)
                .thenCompose(v -> storage.saveBackupCodes(uuid, backupCodes))
                .thenApply(v -> plaintextCodes);
    }

    /**
     * Verify a 2FA code during login.
     * Also checks backup codes.
     */
    public CompletableFuture<Boolean> verifyCode(
            UUID uuid, TwoFactorMethod method,
            String secret, String code) {

        TwoFactorProvider provider = providers.get(method);
        if (provider == null) {
            return CompletableFuture.completedFuture(false);
        }

        // First try the normal code
        if (provider.verifyCode(secret, code)) {
            return CompletableFuture.completedFuture(true);
        }

        // Then try backup codes
        return tryBackupCode(uuid, code);
    }

    /**
     * Try to use a backup code.
     */
    public CompletableFuture<Boolean> tryBackupCode(
            UUID uuid, String code) {
        return storage.getBackupCodes(uuid).thenCompose(codes -> {
            for (BackupCode bc : codes) {
                if (!bc.isUsed() && BackupCode.verify(code, bc.getCodeHash())) {
                    return storage.markBackupCodeUsed(bc.getId())
                            .thenApply(v -> true);
                }
            }
            return CompletableFuture.completedFuture(false);
        });
    }

    /**
     * Get remaining backup code count.
     */
    public CompletableFuture<Integer> getRemainingBackupCodes(UUID uuid) {
        return storage.getBackupCodes(uuid).thenApply(codes ->
                (int) codes.stream().filter(c -> !c.isUsed()).count()
        );
    }

    /**
     * Regenerate backup codes (invalidates old ones).
     */
    public CompletableFuture<List<String>> regenerateBackupCodes(UUID uuid) {
        int count = config.getBackupCodeCount();
        List<String[]> codePairs = BackupCode.generateCodes(uuid, count);

        List<String> plaintextCodes = new ArrayList<>();
        List<BackupCode> backupCodes = new ArrayList<>();

        for (String[] pair : codePairs) {
            plaintextCodes.add(pair[0]);
            backupCodes.add(new BackupCode(uuid, pair[1]));
        }

        return storage.deleteBackupCodes(uuid)
                .thenCompose(v -> storage.saveBackupCodes(uuid, backupCodes))
                .thenApply(v -> plaintextCodes);
    }

    /**
     * Check if a 2FA method is available.
     */
    public boolean isMethodAvailable(TwoFactorMethod method) {
        TwoFactorProvider provider = providers.get(method);
        return provider != null && provider.isAvailable();
    }

    /**
     * Get all available methods.
     */
    public Set<TwoFactorMethod> getAvailableMethods() {
        Set<TwoFactorMethod> available = new HashSet<>();
        for (var entry : providers.entrySet()) {
            if (entry.getValue().isAvailable()) {
                available.add(entry.getKey());
            }
        }
        return available;
    }

    /**
     * Result of beginning 2FA setup.
     */
    public static class TwoFactorSetupResult {
        private final String secret;
        private final byte[] qrCodePng;
        private final String qrCodeUrl;
        private final TwoFactorMethod method;
    
        public TwoFactorSetupResult(String secret, byte[] qrCodePng,
                String qrCodeUrl, TwoFactorMethod method) {
            this.secret = secret;
            this.qrCodePng = qrCodePng;
            this.qrCodeUrl = qrCodeUrl;
            this.method = method;
        }
    
        public String getSecret() { return secret; }
        public byte[] getQrCodePng() { return qrCodePng; }
        public String getQrCodeUrl() { return qrCodeUrl; }
        public TwoFactorMethod getMethod() { return method; }
    }
    }