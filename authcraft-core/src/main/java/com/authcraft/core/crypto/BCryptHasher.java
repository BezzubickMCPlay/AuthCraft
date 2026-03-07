// com/authcraft/core/crypto/BCryptHasher.java
package com.authcraft.core.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.authcraft.core.api.HashingStrategy;
import com.authcraft.core.config.AuthCraftConfig;

public class BCryptHasher implements HashingStrategy {

    private final int cost;

    public BCryptHasher(AuthCraftConfig config) {
        this.cost = config.getBcryptCost();
    }

    @Override
    public String hash(String password) {
        return BCrypt.withDefaults()
                .hashToString(cost, password.toCharArray());
    }

    @Override
    public boolean verify(String password, String hash) {
        try {
            BCrypt.Result result = BCrypt.verifyer()
                    .verify(password.toCharArray(), hash.toCharArray());
            return result.verified;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean needsRehash(String hash) {
        if (hash == null || !hash.startsWith("$2")) return true;
        try {
            // Extract cost from BCrypt hash: $2a$12$...
            String[] parts = hash.split("\\$");
            if (parts.length < 4) return true;
            int hashCost = Integer.parseInt(parts[2]);
            return hashCost != cost;
        } catch (Exception e) {
            return true;
        }
    }

    @Override
    public String getAlgorithmId() {
        return "bcrypt";
    }
}