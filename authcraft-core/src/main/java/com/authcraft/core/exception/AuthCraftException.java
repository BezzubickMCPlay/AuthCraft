// com/authcraft/core/exception/AuthCraftException.java
package com.authcraft.core.exception;

public class AuthCraftException extends RuntimeException {
    public AuthCraftException(String message) { super(message); }
    public AuthCraftException(String message, Throwable cause) {
        super(message, cause);
    }
}