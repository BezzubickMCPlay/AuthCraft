// com/authcraft/core/api/TwoFactorProvider.java
package com.authcraft.core.api;

import com.authcraft.core.model.TwoFactorMethod;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Provider for different 2FA methods.
 */
public interface TwoFactorProvider {

    /**
     * Get the method this provider handles.
     */
    TwoFactorMethod getMethod();

    /**
     * Generate a new secret for setup.
     * For TOTP: returns Base32 secret.
     * For Telegram/VK: returns a link code.
     */
    String generateSecret(UUID playerUuid, String username);

    /**
     * Verify a code against the stored secret.
     */
    boolean verifyCode(String secret, String code);

    /**
     * Send a verification code (for Telegram/VK/Email).
     * For TOTP, this is a no-op.
     */
    CompletableFuture<Boolean> sendCode(String target, String code);

    /**
     * Generate a QR code image URL or data (TOTP only).
     */
    byte[] generateQrCode(String secret, String username, int size);

    /**
     * Is this provider available/configured?
     */
    boolean isAvailable();
}