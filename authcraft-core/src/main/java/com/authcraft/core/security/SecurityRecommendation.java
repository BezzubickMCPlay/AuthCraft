// com/authcraft/core/security/SecurityRecommendation.java
package com.authcraft.core.security;

/**
 * Represents a security recommendation for a player or the server.
 */
public class SecurityRecommendation {

    private final String id;
    private final String severity;
    private final String title;
    private final String description;
    private final String action;
    private final int priority;

    /**
     * Create a new security recommendation.
     *
     * @param id Unique identifier for this recommendation type
     * @param severity Severity level: HIGH, MEDIUM, LOW
     * @param title Short title of the recommendation
     * @param description Detailed description of the security issue
     * @param action Suggested action to resolve the issue
     * @param priority Priority score (higher = more important)
     */
    public SecurityRecommendation(String id, String severity, String title,
                                  String description, String action, int priority) {
        this.id = id;
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.action = action;
        this.priority = priority;
    }

    public String getId() {
        return id;
    }

    public String getSeverity() {
        return severity;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getAction() {
        return action;
    }

    public int getPriority() {
        return priority;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s (Action: %s)", severity, title, description, action);
    }

    /**
     * Get a formatted message for display to players.
     */
    public String toPlayerMessage() {
        StringBuilder sb = new StringBuilder();
        sb.append("§c§lSecurity Recommendation§r\n");
        sb.append("§e").append(title).append("§r\n");
        sb.append("§7").append(description).append("§r\n");
        sb.append("§aSuggested action: §f").append(action).append("§r");
        return sb.toString();
    }

    /**
     * Get a formatted message for admin display.
     */
    public String toAdminMessage() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(severity).append("] ");
        sb.append(title).append("\n");
        sb.append("  Description: ").append(description).append("\n");
        sb.append("  Action: ").append(action).append("\n");
        sb.append("  Priority: ").append(priority);
        return sb.toString();
    }
}
