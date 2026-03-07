// com/authcraft/core/api/HashingStrategy.java
package com.authcraft.core.api;

/**
 * Strategy pattern for password hashing algorithms.
 */
public interface HashingStrategy {

    /**
     * Hash a raw password.
     */
    String hash(String password);

    /**
     * Verify a password against a stored hash.
     * Must use constant-time comparison.
     */
    boolean verify(String password, String hash);

    /**
     * Check if this hash needs to be re-hashed
     * (e.g. cost factor changed).
     */
    boolean needsRehash(String hash);

    /**
     * Algorithm identifier.
     */
    String getAlgorithmId();
}