// com/authcraft/core/crypto/LegacyMD5Hasher.java
package com.authcraft.core.crypto;

import com.authcraft.core.api.HashingStrategy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * MD5 hashing — for MIGRATION ONLY.
 */
public class LegacyMD5Hasher implements HashingStrategy {

    @Override
    public String hash(String password) {
        throw new UnsupportedOperationException(
                "MD5 is insecure and must not be used for new passwords"
        );
    }

    @Override
    public boolean verify(String password, String storedHash) {
        try {
            String computed = md5(password);
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
        return true;
    }

    @Override
    public String getAlgorithmId() {
        return "md5";
    }

    private String md5(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(
                    input.getBytes(StandardCharsets.UTF_8)
            );
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}