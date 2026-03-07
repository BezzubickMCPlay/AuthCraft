// com/authcraft/core/exception/RateLimitException.java
package com.authcraft.core.exception;

public class RateLimitException extends AuthCraftException {
    private final long retryAfterSeconds;

    public RateLimitException(long retryAfterSeconds) {
        super("Rate limited. Retry after " + retryAfterSeconds + "s");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() { return retryAfterSeconds; }
}