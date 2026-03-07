// com/authcraft/core/crypto/LegacySHA256Hasher.java
package com.authcraft.core.crypto;

import com.authcraft.core.api.HashingStrategy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 hashing — for MIGRATION ONLY.
 * Format: $SHA$salt$hash (AuthMe-compatible)
 */
public class LegacySHA256Hasher implements HashingStrategy {

    @Override
    public String hash(String password) {
        throw new UnsupportedOperationException(
                "SHA-256 hashing is insecure and should not be used for new passwords"
        );
    }

    @Override
    public boolean verify(String password, String storedHash) {
        try {
            if (storedHash.startsWith("$SHA$")) {
                // AuthMe SHA-256 format: $SHA$salt$hash
                String[] parts = storedHash.split("\\$");
                if (parts.length < 4) return false;
                String salt = parts[2];
                String expected = parts[3];
                String computed = sha256(sha256(password) + salt);
                // Use constant-time comparison with explicit UTF-8 encoding
                return MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.UTF_8),
                    computed.getBytes(StandardCharsets.UTF_8)
                );
            }
            // Plain SHA-256
            String computed = sha256(password);
            // Use constant-time comparison with explicit UTF-8 encoding
            return MessageDigest.isEqual(
                storedHash.toLowerCase().getBytes(StandardCharsets.UTF_8),
                computed.toLowerCase().getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean needsRehash(String hash) {
        return true; // Always rehash legacy
    }

    @Override
    public String getAlgorithmId() {
        return "sha256";
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(
                    input.getBytes(StandardCharsets.UTF_8)
            );
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}