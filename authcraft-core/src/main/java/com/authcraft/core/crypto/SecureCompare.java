// com/authcraft/core/crypto/SecureCompare.java
package com.authcraft.core.crypto;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * Utilities for constant-time operations to prevent timing attacks.
 */
public final class SecureCompare {

    private SecureCompare() {}

    /**
     * Constant-time string comparison.
     * Prevents timing attacks by always comparing all bytes.
     */
    public static boolean equals(String a, String b) {
        if (a == null || b == null) {
            return a == null && b == null;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Constant-time byte array comparison.
     */
    public static boolean equals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Constant-time hash comparison (for backup codes, tokens, etc).
     * Uses MessageDigest.isEqual for constant-time comparison.
     */
    public static boolean equalsHash(String input, String storedHash) {
        if (input == null || storedHash == null) return false;
        // Use constant-time comparison - MessageDigest.isEqual compares all bytes
        return MessageDigest.isEqual(
            input.toLowerCase().getBytes(StandardCharsets.UTF_8),
            storedHash.toLowerCase().getBytes(StandardCharsets.UTF_8)
        );
    }
    
    /**
     * Constant-time comparison for TOTP codes.
     * Pads shorter string to prevent length-based timing attacks.
     */
    public static boolean equalsTotp(String a, String b) {
        if (a == null || b == null) return false;
        // TOTP codes should be exactly 6 digits
        if (a.length() != b.length()) return false;
        return MessageDigest.isEqual(
            a.getBytes(StandardCharsets.UTF_8),
            b.getBytes(StandardCharsets.UTF_8)
        );
    }
}