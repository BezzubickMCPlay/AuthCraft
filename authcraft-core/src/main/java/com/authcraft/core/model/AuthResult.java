// com/authcraft/core/model/AuthResult.java
package com.authcraft.core.model;

public class AuthResult {

    public enum Status {
        SUCCESS,
        INVALID_PASSWORD,
        ACCOUNT_LOCKED,
        ACCOUNT_NOT_FOUND,
        REQUIRES_2FA,
        INVALID_2FA_CODE,
        SESSION_RESTORED,
        REGISTRATION_REQUIRED,
        RATE_LIMITED,
        GEO_BLOCKED,
        BOT_DETECTED,
        UNICODE_SPOOF,
        ERROR
    }

    private final Status status;
    private final String message;
    private final Session session;

    private AuthResult(Status status, String message, Session session) {
        this.status = status;
        this.message = message;
        this.session = session;
    }

    public static AuthResult success(Session session) {
        return new AuthResult(Status.SUCCESS, "Login successful", session);
    }

    public static AuthResult sessionRestored(Session session) {
        return new AuthResult(Status.SESSION_RESTORED,
                "Session restored", session);
    }

    public static AuthResult requires2FA() {
        return new AuthResult(Status.REQUIRES_2FA,
                "2FA code required", null);
    }

    public static AuthResult failure(Status status, String message) {
        return new AuthResult(status, message, null);
    }

    public boolean isSuccessful() {
        return status == Status.SUCCESS || status == Status.SESSION_RESTORED;
    }

    public Status getStatus() { return status; }
    public String getMessage() { return message; }
    public Session getSession() { return session; }
}