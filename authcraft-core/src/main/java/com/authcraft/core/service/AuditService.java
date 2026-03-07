// com/authcraft/core/service/AuditService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.AuditEventType;

import java.io.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

/**
 * Handles audit logging to file and/or database.
 * Notifies admins about security events.
 */
public class AuditService {

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

    private final StorageProvider storage;
    private final PlatformAdapter platform;
    private final AuthCraftConfig config;
    private final Logger logger;

    private PrintWriter fileWriter;

    public AuditService(StorageProvider storage,
                        PlatformAdapter platform,
                        AuthCraftConfig config) {
        this.storage = storage;
        this.platform = platform;
        this.config = config;
        this.logger = platform.getLogger();

        if (config.isAuditLogToFile()) {
            initFileWriter();
        }
    }

    private void initFileWriter() {
        try {
            File logDir = new File(platform.getDataFolder(), "logs");
            if (!logDir.exists()) logDir.mkdirs();

            String dateStr = DateTimeFormatter.ofPattern("yyyy-MM-dd")
                    .withZone(ZoneId.systemDefault())
                    .format(Instant.now());

            File logFile = new File(logDir, "audit-" + dateStr + ".log");
            fileWriter = new PrintWriter(
                    new BufferedWriter(
                            new FileWriter(logFile, true)
                    ),
                    true // auto-flush
            );
        } catch (IOException e) {
            logger.warning("[AuthCraft] Failed to init audit log file: "
                    + e.getMessage());
        }
    }

    /**
     * Log an audit event.
     */
    public CompletableFuture<Void> log(AuditEventType type,
                                       UUID uuid,
                                       String username,
                                       String ip,
                                       String details) {
        AuditEvent event = AuditEvent.of(type, uuid, username, ip, details);

        // Console log
        String logLine = formatLogLine(event);
        logger.info(logLine);

        // File log
        if (config.isAuditLogToFile() && fileWriter != null) {
            fileWriter.println(logLine);
        }

        // Database log
        CompletableFuture<Void> dbFuture;
        if (config.isAuditLogToDatabase()) {
            dbFuture = storage.logEvent(event);
        } else {
            dbFuture = CompletableFuture.completedFuture(null);
        }

        // Admin notifications for critical events
        if (isNotifiableEvent(type)) {
            notifyAdmins(event);
        }

        return dbFuture;
    }

    /**
     * Shorthand: log with no UUID/username (system events).
     */
    public CompletableFuture<Void> logSystem(AuditEventType type,
                                             String details) {
        return log(type, null, "SYSTEM", "localhost", details);
    }

    private String formatLogLine(AuditEvent event) {
        return String.format("[%s] [%s] user=%s ip=%s %s",
                FORMATTER.format(event.getTimestamp()),
                event.getEventType().name(),
                event.getUsername() != null ? event.getUsername() : "N/A",
                event.getIpAddress() != null ? event.getIpAddress() : "N/A",
                event.getDetails() != null ? event.getDetails() : ""
        );
    }

    private boolean isNotifiableEvent(AuditEventType type) {
        return switch (type) {
            case LOGIN_FAILURE,
                 ACCOUNT_LOCKED,
                 IP_BLOCKED,
                 BOT_DETECTED,
                 UNICODE_SPOOF_DETECTED,
                 SECURITY_AUDIT -> true;
            default -> false;
        };
    }

    private void notifyAdmins(AuditEvent event) {
        String message = "§c[AuthCraft Security] §f"
                + event.getEventType().name() + ": "
                + (event.getUsername() != null ? event.getUsername() : "")
                + " [" + (event.getIpAddress() != null
                ? event.getIpAddress() : "") + "] "
                + (event.getDetails() != null ? event.getDetails() : "");

        platform.broadcastPermission(
                message, "authcraft.admin.notify"
        );
    }

    /**
     * Close file writer on shutdown.
     */
    public void shutdown() {
        if (fileWriter != null) {
            fileWriter.flush();
            fileWriter.close();
        }
    }
}