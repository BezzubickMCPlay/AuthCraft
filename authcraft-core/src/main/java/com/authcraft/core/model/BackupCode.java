// com/authcraft/core/model/BackupCode.java
package com.authcraft.core.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

public class BackupCode {

    private long id;
    private UUID playerUuid;
    private String codeHash;
    private boolean used;

    private static final SecureRandom RANDOM = new SecureRandom();

    public BackupCode() {}

    public BackupCode(UUID playerUuid, String codeHash) {
        this.playerUuid = playerUuid;
        this.codeHash = codeHash;
        this.used = false;
    }

    /**
     * Generate a set of backup codes.
     * Returns: List of [plaintext, hashed] pairs.
     */
    public static List<String[]> generateCodes(UUID playerUuid, int count) {
        List<String[]> codes = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String plain = generateCodeString();
            String hash = hashCode256(plain);
            codes.add(new String[]{plain, hash});
        }
        return codes;
    }

    private static String generateCodeString() {
        // Format: XXXX-XXXX
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == 4) sb.append('-');
            sb.append((char) ('A' + RANDOM.nextInt(26)));
        }
        return sb.toString();
    }

    public static String hashCode256(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Use UTF-8 encoding for consistent results across platforms
            byte[] hash = digest.digest(code.replace("-", "").toUpperCase().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static boolean verify(String inputCode, String storedHash) {
        String inputHash = hashCode256(inputCode);
        // Use constant-time comparison to prevent timing attacks
        return MessageDigest.isEqual(
            inputHash.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            storedHash.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public UUID getPlayerUuid() { return playerUuid; }
    public void setPlayerUuid(UUID uuid) { this.playerUuid = uuid; }

    public String getCodeHash() { return codeHash; }
    public void setCodeHash(String hash) { this.codeHash = hash; }

    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }
}