// com/authcraft/core/exception/AccountLockedException.java
package com.authcraft.core.exception;

import java.time.Instant;

public class AccountLockedException extends AuthCraftException {
    private final Instant lockedUntil;

    public AccountLockedException(Instant lockedUntil) {
        super("Account is locked until " + lockedUntil);
        this.lockedUntil = lockedUntil;
    }

    public Instant getLockedUntil() { return lockedUntil; }
}