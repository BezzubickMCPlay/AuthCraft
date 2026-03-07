// com/authcraft/core/model/HashAlgorithm.java
package com.authcraft.core.model;

public enum HashAlgorithm {
    ARGON2ID("argon2id"),
    BCRYPT("bcrypt"),
    PBKDF2("pbkdf2"),
    // Legacy — for migration only
    SHA256("sha256"),
    MD5("md5"),
    AUTHME("authme"),
    XAUTH("xauth"),
    WORDPRESS("wordpress");

    private final String id;

    HashAlgorithm(String id) {
        this.id = id;
    }

    public String getId() { return id; }

    public static HashAlgorithm fromId(String id) {
        for (HashAlgorithm alg : values()) {
            if (alg.id.equalsIgnoreCase(id)) return alg;
        }
        return ARGON2ID;
    }

    public boolean isLegacy() {
        return this == SHA256 || this == MD5 || this == AUTHME
                || this == XAUTH || this == WORDPRESS;
    }
}