// com/authcraft/core/exception/WeakPasswordException.java
package com.authcraft.core.exception;

import java.util.List;

public class WeakPasswordException extends AuthCraftException {
    private final List<String> violations;

    public WeakPasswordException(List<String> violations) {
        super("Password does not meet requirements: "
                + String.join(", ", violations));
        this.violations = violations;
    }

    public List<String> getViolations() { return violations; }
}