// com/authcraft/core/crypto/Argon2idHasher.java
package com.authcraft.core.crypto;

import com.authcraft.core.api.HashingStrategy;
import com.authcraft.core.config.AuthCraftConfig;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class Argon2idHasher implements HashingStrategy {

    private final Argon2 argon2;
    private final int iterations;
    private final int memory;
    private final int parallelism;

    public Argon2idHasher(AuthCraftConfig config) {
        this.argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        this.iterations = config.getArgon2Iterations();
        this.memory = config.getArgon2Memory();
        this.parallelism = config.getArgon2Parallelism();
    }

    @Override
    public String hash(String password) {
        try {
            return argon2.hash(iterations, memory, parallelism,
                    password.toCharArray());
        } finally {
            // Argon2 library handles char[] wiping internally
        }
    }

    @Override
    public boolean verify(String password, String hash) {
        try {
            return argon2.verify(hash, password.toCharArray());
        } catch (Exception e) {
            return false;
        }
    }

    // com/authcraft/core/crypto/Argon2idHasher.java — COMPATIBLE VERSION
// Заменяем switch expressions на if-else для Java 8-16 серверов:

    @Override
    public boolean needsRehash(String hash) {
        if (hash == null || !hash.startsWith("$argon2id$")) {
            return true;
        }
        try {
            String[] parts = hash.split("\\$");
            if (parts.length < 4) return true;

            String params = parts[3];
            String[] paramParts = params.split(",");

            int hashMemory = 0, hashIterations = 0, hashParallelism = 0;
            for (String param : paramParts) {
                String[] kv = param.split("=");
                if (kv.length != 2) continue;
                if ("m".equals(kv[0])) hashMemory = Integer.parseInt(kv[1]);
                else if ("t".equals(kv[0])) hashIterations = Integer.parseInt(kv[1]);
                else if ("p".equals(kv[0])) hashParallelism = Integer.parseInt(kv[1]);
            }

            return hashMemory != memory
                    || hashIterations != iterations
                    || hashParallelism != parallelism;
        } catch (Exception e) {
            return true;
        }
    }

    @Override
    public String getAlgorithmId() {
        return "argon2id";
    }
}