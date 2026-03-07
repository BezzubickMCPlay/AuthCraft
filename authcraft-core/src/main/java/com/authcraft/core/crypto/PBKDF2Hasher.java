// com/authcraft/core/crypto/PBKDF2Hasher.java
package com.authcraft.core.crypto;

import com.authcraft.core.api.HashingStrategy;
import com.authcraft.core.config.AuthCraftConfig;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PBKDF2Hasher implements HashingStrategy {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final String PREFIX = "$pbkdf2$";

    private final int iterations;
    private final SecureRandom secureRandom;

    public PBKDF2Hasher(AuthCraftConfig config) {
        this.iterations = config.getPbkdf2Iterations();
        this.secureRandom = new SecureRandom();
    }

    @Override
    public String hash(String password) {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);

        byte[] hash = pbkdf2(password.toCharArray(), salt, iterations);

        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);

        // Format: $pbkdf2$iterations$salt$hash
        return PREFIX + iterations + "$" + saltBase64 + "$" + hashBase64;
    }

    @Override
    public boolean verify(String password, String storedHash) {
        try {
            if (!storedHash.startsWith(PREFIX)) return false;

            String[] parts = storedHash.substring(PREFIX.length())
                .split("\\$");
            if (parts.length != 3) return false;

            int storedIterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[2]);

            byte[] computedHash = pbkdf2(
                password.toCharArray(), salt, storedIterations
            );

            // Use constant-time comparison to prevent timing attacks
            return MessageDigest.isEqual(expectedHash, computedHash);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean needsRehash(String hash) {
        if (hash == null || !hash.startsWith(PREFIX)) return true;
        try {
            String[] parts = hash.substring(PREFIX.length()).split("\\$");
            int storedIterations = Integer.parseInt(parts[0]);
            return storedIterations != iterations;
        } catch (Exception e) {
            return true;
        }
    }

    @Override
    public String getAlgorithmId() {
        return "pbkdf2";
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password, salt, iterations, KEY_LENGTH
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2 computation failed", e);
        }
    }
}