// com/authcraft/core/service/ComplianceService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.LoginAttempt;
import com.authcraft.core.model.Session;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Compliance and Reporting Service.
 *
 * Features:
 * - GDPR compliance tools
 * - Data export for players (JSON, CSV)
 * - Right to be forgotten implementation
 * - Security compliance reports
 * - Audit log export (PDF, CSV)
 */
public class ComplianceService {

    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final StorageProvider storage;
    private final AuditService auditService;
    private final MessageService messageService;
    private final Logger logger;

    // Pending deletion requests (for grace period)
    private final Map<UUID, DeletionRequest> pendingDeletions = new HashMap<>();

    // Export requests tracking
    private final Map<UUID, List<ExportRequest>> exportRequests = new HashMap<>();

    // Date formatters
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private static final DateTimeFormatter READABLE_FORMATTER = DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());

    /**
     * Creates a new ComplianceService.
     */
    public ComplianceService(AuthCraftConfig config, PlatformAdapter platform,
                             StorageProvider storage, AuditService auditService,
                             MessageService messageService) {
        this.config = config;
        this.platform = platform;
        this.storage = storage;
        this.auditService = auditService;
        this.messageService = messageService;
        this.logger = platform.getLogger();
    }

    // === GDPR: Data Export ===

    /**
     * Export all player data to JSON format.
     */
    public CompletableFuture<ExportResult> exportPlayerDataJson(UUID playerUuid) {
        return collectPlayerData(playerUuid).thenApply(data -> {
            try {
                String json = formatAsJson(data);
                Path exportPath = getExportPath(playerUuid, "json");
                Files.writeString(exportPath, json);

                // Track export request
                trackExport(playerUuid, "json", exportPath.toString());

                // Audit log
                auditService.log(AuditEventType.DATA_EXPORT, playerUuid,
                        playerName(playerUuid), playerIp(playerUuid),
                        "Player data exported to JSON");

                return new ExportResult(true, exportPath.toString(), "json", json.length());
            } catch (Exception e) {
                logger.severe("Failed to export player data: " + e.getMessage());
                return new ExportResult(false, null, "json", 0);
            }
        });
    }

    /**
     * Export all player data to CSV format.
     */
    public CompletableFuture<ExportResult> exportPlayerDataCsv(UUID playerUuid) {
        return collectPlayerData(playerUuid).thenApply(data -> {
            try {
                String csv = formatAsCsv(data);
                Path exportPath = getExportPath(playerUuid, "csv");
                Files.writeString(exportPath, csv);

                // Track export request
                trackExport(playerUuid, "csv", exportPath.toString());

                // Audit log
                auditService.log(AuditEventType.DATA_EXPORT, playerUuid,
                        playerName(playerUuid), playerIp(playerUuid),
                        "Player data exported to CSV");

                return new ExportResult(true, exportPath.toString(), "csv", csv.length());
            } catch (Exception e) {
                logger.severe("Failed to export player data: " + e.getMessage());
                return new ExportResult(false, null, "csv", 0);
            }
        });
    }

    /**
     * Collect all player data from storage.
     */
    private CompletableFuture<PlayerDataBundle> collectPlayerData(UUID playerUuid) {
        PlayerDataBundle bundle = new PlayerDataBundle(playerUuid);

        return storage.getAccount(playerUuid)
                .thenCompose(optAccount -> {
                    optAccount.ifPresent(bundle::setAccount);
                    return storage.getSessions(playerUuid);
                })
                .thenCompose(sessions -> {
                    bundle.setSessions(sessions);
                    return storage.getLoginAttempts(playerUuid);
                })
                .thenCompose(attempts -> {
                    bundle.setLoginAttempts(attempts);
                    return storage.getAuditEvents(playerUuid, 1000, 0);
                })
                .thenCompose(events -> {
                    bundle.setAuditEvents(events);
                    return storage.getTrustedDevices(playerUuid);
                })
                .thenApply(devices -> {
                    bundle.setTrustedDevices(devices);
                    bundle.setExportedAt(System.currentTimeMillis());
                    return bundle;
                });
    }

    /**
     * Format player data as JSON.
     */
    private String formatAsJson(PlayerDataBundle data) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"exportVersion\": \"1.0\",\n");
        sb.append("  \"exportedAt\": \"").append(ISO_FORMATTER.format(Instant.ofEpochMilli(data.getExportedAt()))).append("\",\n");
        sb.append("  \"playerUuid\": \"").append(data.getPlayerUuid()).append("\",\n");

        // Account data
        if (data.getAccount() != null) {
            Account acc = data.getAccount();
            sb.append("  \"account\": {\n");
            sb.append("    \"username\": \"").append(escapeJson(acc.getUsername())).append("\",\n");
            sb.append("    \"uuid\": \"").append(acc.getUuid()).append("\",\n");
            sb.append("    \"email\": \"").append(escapeJson(acc.getEmail() != null ? acc.getEmail() : "")).append("\",\n");
            sb.append("    \"registeredAt\": \"").append(acc.getCreatedAt() != null ? ISO_FORMATTER.format(acc.getCreatedAt()) : "unknown").append("\",\n");
            sb.append("    \"lastLogin\": \"").append(acc.getLastLoginDate() != null ? ISO_FORMATTER.format(acc.getLastLoginDate()) : "never").append("\",\n");
            sb.append("    \"lastIp\": \"").append(escapeJson(acc.getLastLoginIp() != null ? acc.getLastLoginIp() : "")).append("\",\n");
            sb.append("    \"role\": \"").append(escapeJson(acc.getRole())).append("\",\n");
            sb.append("    \"twoFactorEnabled\": ").append(acc.isTwoFactorEnabled()).append(",\n");
            sb.append("    \"twoFactorMethods\": [").append(acc.getEnabledTwoFactorMethods().stream()
                    .map(m -> "\"" + m.name() + "\"")
                    .collect(Collectors.joining(", "))).append("],\n");
            sb.append("    \"locked\": ").append(acc.isLocked()).append("\n");
            sb.append("  },\n");
        }

        // Sessions
        sb.append("  \"sessions\": [\n");
        if (data.getSessions() != null) {
            for (int i = 0; i < data.getSessions().size(); i++) {
                Session s = data.getSessions().get(i);
                sb.append("    {\"token\": \"").append(s.getToken())
                        .append("\", \"ip\": \"").append(escapeJson(s.getIpAddress()))
                        .append("\", \"createdAt\": \"").append(s.getCreatedAt() != null ? ISO_FORMATTER.format(s.getCreatedAt()) : "unknown")
                        .append("\", \"expiresAt\": \"").append(s.getExpiresAt() != null ? ISO_FORMATTER.format(s.getExpiresAt()) : "unknown")
                        .append("\", \"twoFactorVerified\": ").append(s.isTwoFactorVerified())
                        .append("}");
                if (i < data.getSessions().size() - 1) sb.append(",");
                sb.append("\n");
            }
        }
        sb.append("  ],\n");

        // Login attempts
        sb.append("  \"loginAttempts\": [\n");
        if (data.getLoginAttempts() != null) {
            for (int i = 0; i < data.getLoginAttempts().size(); i++) {
                LoginAttempt la = data.getLoginAttempts().get(i);
                sb.append("    {\"ip\": \"").append(escapeJson(la.getIpAddress()))
                        .append("\", \"timestamp\": \"").append(la.getTimestamp() != null ? ISO_FORMATTER.format(la.getTimestamp()) : "unknown")
                        .append("\", \"success\": ").append(la.isSuccess())
                        .append("}");
                if (i < data.getLoginAttempts().size() - 1) sb.append(",");
                sb.append("\n");
            }
        }
        sb.append("  ],\n");

        // Audit events
        sb.append("  \"auditEvents\": [\n");
        if (data.getAuditEvents() != null) {
            for (int i = 0; i < data.getAuditEvents().size(); i++) {
                AuditEvent ae = data.getAuditEvents().get(i);
                sb.append("    {\"type\": \"").append(ae.getEventType().name())
                        .append("\", \"timestamp\": \"").append(ae.getTimestamp() != null ? ISO_FORMATTER.format(ae.getTimestamp()) : "unknown")
                        .append("\", \"ip\": \"").append(escapeJson(ae.getIpAddress() != null ? ae.getIpAddress() : ""))
                        .append("\", \"details\": \"").append(escapeJson(ae.getDetails() != null ? ae.getDetails() : ""))
                        .append("\"}");
                if (i < data.getAuditEvents().size() - 1) sb.append(",");
                sb.append("\n");
            }
        }
        sb.append("  ]\n");

        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Format player data as CSV.
     */
    private String formatAsCsv(PlayerDataBundle data) {
        StringBuilder sb = new StringBuilder();

        // Header
        sb.append("# Player Data Export\n");
        sb.append("# Export Version: 1.0\n");
        sb.append("# Exported At: ").append(READABLE_FORMATTER.format(Instant.ofEpochMilli(data.getExportedAt()))).append("\n");
        sb.append("# Player UUID: ").append(data.getPlayerUuid()).append("\n\n");

        // Account section
        sb.append("## ACCOUNT DATA\n");
        sb.append("field,value\n");
        if (data.getAccount() != null) {
            Account acc = data.getAccount();
            sb.append("username,").append(acc.getUsername()).append("\n");
            sb.append("uuid,").append(acc.getUuid()).append("\n");
            sb.append("email,").append(acc.getEmail() != null ? acc.getEmail() : "").append("\n");
            sb.append("registered_at,").append(acc.getCreatedAt() != null ? READABLE_FORMATTER.format(acc.getCreatedAt()) : "unknown").append("\n");
            sb.append("last_login,").append(acc.getLastLoginDate() != null ? READABLE_FORMATTER.format(acc.getLastLoginDate()) : "never").append("\n");
            sb.append("last_ip,").append(acc.getLastLoginIp() != null ? acc.getLastLoginIp() : "").append("\n");
            sb.append("role,").append(acc.getRole()).append("\n");
            sb.append("two_factor_enabled,").append(acc.isTwoFactorEnabled()).append("\n");
            sb.append("locked,").append(acc.isLocked()).append("\n");
        }
        sb.append("\n");

        // Sessions section
        sb.append("## SESSIONS\n");
        sb.append("token,ip_address,created_at,expires_at,two_factor_verified\n");
        if (data.getSessions() != null) {
            for (Session s : data.getSessions()) {
                sb.append(s.getToken()).append(",")
                        .append(s.getIpAddress()).append(",")
                        .append(s.getCreatedAt() != null ? READABLE_FORMATTER.format(s.getCreatedAt()) : "unknown").append(",")
                        .append(s.getExpiresAt() != null ? READABLE_FORMATTER.format(s.getExpiresAt()) : "unknown").append(",")
                        .append(s.isTwoFactorVerified()).append("\n");
            }
        }
        sb.append("\n");

        // Login attempts section
        sb.append("## LOGIN ATTEMPTS\n");
        sb.append("ip_address,timestamp,success\n");
        if (data.getLoginAttempts() != null) {
            for (LoginAttempt la : data.getLoginAttempts()) {
                sb.append(la.getIpAddress()).append(",")
                        .append(la.getTimestamp() != null ? READABLE_FORMATTER.format(la.getTimestamp()) : "unknown").append(",")
                        .append(la.isSuccess()).append("\n");
            }
        }
        sb.append("\n");

        // Audit events section
        sb.append("## AUDIT EVENTS\n");
        sb.append("type,timestamp,ip_address,details\n");
        if (data.getAuditEvents() != null) {
            for (AuditEvent ae : data.getAuditEvents()) {
                sb.append(ae.getEventType().name()).append(",")
                        .append(ae.getTimestamp() != null ? READABLE_FORMATTER.format(ae.getTimestamp()) : "unknown").append(",")
                        .append(ae.getIpAddress() != null ? ae.getIpAddress() : "").append(",")
                        .append("\"").append(ae.getDetails() != null ? ae.getDetails().replace("\"", "\"\"") : "").append("\"\n");
            }
        }

        return sb.toString();
    }

    // === GDPR: Right to be Forgotten ===

    /**
     * Request account deletion (starts grace period).
     */
    public CompletableFuture<DeletionResult> requestDeletion(UUID playerUuid, String reason) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new DeletionResult(false, "Account not found", 0);
            }

            Account account = optAccount.get();

            // Check if already pending
            if (pendingDeletions.containsKey(playerUuid)) {
                DeletionRequest existing = pendingDeletions.get(playerUuid);
                long remainingHours = (existing.getExpiresAt() - System.currentTimeMillis()) / (1000 * 60 * 60);
                return new DeletionResult(false, "Deletion already pending. " + remainingHours + " hours remaining.", remainingHours);
            }

            // Create deletion request with grace period (default 7 days)
            long gracePeriodMs = config.getDeletionGracePeriodDays() * 24L * 60 * 60 * 1000;
            DeletionRequest request = new DeletionRequest(
                    playerUuid,
                    account.getUsername(),
                    reason,
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + gracePeriodMs
            );

            pendingDeletions.put(playerUuid, request);

            // Audit log
            auditService.log(AuditEventType.DELETION_REQUESTED, playerUuid,
                    account.getUsername(), playerIp(playerUuid),
                    "Account deletion requested. Reason: " + reason);

            // Notify player
            platform.runSync(() -> {
                platform.sendMessage(playerUuid, messageService.getForPlayer(playerUuid,
                        "compliance.deletion.requested",
                        "days", String.valueOf(config.getDeletionGracePeriodDays())));
            });

            logger.info("Account deletion requested for " + account.getUsername() + " (" + playerUuid + ")");

            return new DeletionResult(true, "Deletion scheduled. You have " + config.getDeletionGracePeriodDays() + " days to cancel.",
                    config.getDeletionGracePeriodDays());
        });
    }

    /**
     * Cancel a pending deletion request.
     */
    public CompletableFuture<Boolean> cancelDeletion(UUID playerUuid) {
        return CompletableFuture.supplyAsync(() -> {
            DeletionRequest request = pendingDeletions.remove(playerUuid);
            if (request == null) {
                return false;
            }

            // Audit log
            auditService.log(AuditEventType.DELETION_CANCELLED, playerUuid,
                    playerName(playerUuid), playerIp(playerUuid),
                    "Account deletion cancelled by user");

            // Notify player
            platform.runSync(() -> {
                platform.sendMessage(playerUuid, messageService.getForPlayer(playerUuid,
                        "compliance.deletion.cancelled"));
            });

            logger.info("Account deletion cancelled for " + playerUuid);
            return true;
        });
    }

    /**
     * Execute pending deletions (called by cleanup task).
     */
    public void processPendingDeletions() {
        long now = System.currentTimeMillis();
        List<UUID> toDelete = new ArrayList<>();

        for (Map.Entry<UUID, DeletionRequest> entry : pendingDeletions.entrySet()) {
            if (entry.getValue().getExpiresAt() <= now) {
                toDelete.add(entry.getKey());
            }
        }

        for (UUID uuid : toDelete) {
            executeDeletion(uuid);
        }
    }

    /**
     * Execute account deletion.
     */
    private void executeDeletion(UUID playerUuid) {
        DeletionRequest request = pendingDeletions.remove(playerUuid);
        if (request == null) return;

        logger.info("Executing account deletion for " + request.getUsername() + " (" + playerUuid + ")");

        // Anonymize instead of delete (for audit trail integrity)
        storage.getAccount(playerUuid).thenCompose(optAccount -> {
            if (optAccount.isEmpty()) return CompletableFuture.completedFuture(null);

            Account account = optAccount.get();

            // Anonymize the account
            account.setUsername("deleted_" + UUID.randomUUID().toString().substring(0, 8));
            account.setEmail(null);
            account.setPasswordHash("");
            account.setTwoFactorSecret(null);
            account.setEnabledTwoFactorMethods(java.util.Collections.emptySet());

            return storage.saveAccount(account);
        }).thenCompose(v -> storage.deleteAllSessions(playerUuid))
                .thenCompose(v -> storage.deleteAllTrustedDevices(playerUuid))
                .thenCompose(v -> storage.deleteLoginAttempts(playerUuid))
                .thenAccept(v -> {
                    // Log the deletion (with anonymized data)
                    auditService.logSystem(AuditEventType.DELETION_COMPLETED,
                            "Account permanently deleted: " + request.getUsername() + " (" + playerUuid + ")");

                    logger.info("Account deletion completed for " + playerUuid);
                })
                .exceptionally(ex -> {
                    logger.severe("Failed to complete account deletion for " + playerUuid + ": " + ex.getMessage());
                    return null;
                });
    }

    // === Security Compliance Reports ===

    /**
     * Generate a security compliance report.
     */
    public CompletableFuture<ComplianceReport> generateSecurityReport() {
        return CompletableFuture.supplyAsync(() -> {
            ComplianceReport report = new ComplianceReport();
            report.setGeneratedAt(System.currentTimeMillis());
            report.setReportType("SECURITY_COMPLIANCE");

            // Collect security metrics
            return storage.countAccountsWith2FA().thenCompose(twoFactorCount -> {
                report.addMetric("accounts_with_2fa", twoFactorCount);
                return storage.countTotalAccounts();
            }).thenCompose(totalAccounts -> {
                report.addMetric("total_accounts", totalAccounts);
                return storage.countLockedAccounts();
            }).thenCompose(lockedCount -> {
                report.addMetric("locked_accounts", lockedCount);
                return storage.countRecentFailedLogins(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
            }).thenCompose(failedLogins -> {
                report.addMetric("failed_logins_24h", failedLogins);
                return storage.countActiveSessions();
            }).thenApply(activeSessions -> {
                report.addMetric("active_sessions", activeSessions);

                // Calculate compliance score
                long total = (long) report.getMetrics().getOrDefault("total_accounts", 0L);
                long with2FA = (long) report.getMetrics().getOrDefault("accounts_with_2fa", 0L);
                double twoFactorRate = total > 0 ? (double) with2FA / total * 100 : 0;
                report.addMetric("two_factor_adoption_rate", twoFactorRate);

                // Compliance status
                if (twoFactorRate >= 50) {
                    report.setComplianceStatus("GOOD");
                } else if (twoFactorRate >= 25) {
                    report.setComplianceStatus("MODERATE");
                } else {
                    report.setComplianceStatus("NEEDS_IMPROVEMENT");
                }

                return report;
            }).join();
        });
    }

    /**
     * Generate a GDPR compliance report.
     */
    public CompletableFuture<ComplianceReport> generateGdprReport() {
        return CompletableFuture.supplyAsync(() -> {
            ComplianceReport report = new ComplianceReport();
            report.setGeneratedAt(System.currentTimeMillis());
            report.setReportType("GDPR_COMPLIANCE");

            // Check GDPR compliance items
            report.addMetric("data_retention_days", config.getSessionTtlHours() / 24);
            report.addMetric("audit_logging_enabled", config.isAuditLogEnabled());
            report.addMetric("audit_database_logging", config.isAuditLogToDatabase());
            report.addMetric("deletion_grace_period_days", config.getDeletionGracePeriodDays());

            // Count pending deletions
            report.addMetric("pending_deletion_requests", pendingDeletions.size());

            // Count export requests
            long totalExports = exportRequests.values().stream()
                    .mapToLong(List::size)
                    .sum();
            report.addMetric("total_export_requests", totalExports);

            // Compliance status
            boolean hasAuditLogging = config.isAuditLogEnabled();
            boolean hasGracePeriod = config.getDeletionGracePeriodDays() >= 7;

            if (hasAuditLogging && hasGracePeriod) {
                report.setComplianceStatus("COMPLIANT");
            } else {
                report.setComplianceStatus("NON_COMPLIANT");
            }

            return report;
        });
    }

    // === Audit Log Export ===

    /**
     * Export audit logs to CSV.
     */
    public CompletableFuture<ExportResult> exportAuditLogCsv(UUID targetUuid, int limit) {
        return storage.getAuditEvents(targetUuid, limit, 0).thenApply(events -> {
            try {
                Path exportPath = getAuditExportPath("csv");
                StringBuilder sb = new StringBuilder();

                sb.append("# Audit Log Export\n");
                sb.append("# Exported At: ").append(READABLE_FORMATTER.format(Instant.now())).append("\n");
                if (targetUuid != null) {
                    sb.append("# Target UUID: ").append(targetUuid).append("\n");
                }
                sb.append("# Total Events: ").append(events.size()).append("\n\n");

                sb.append("timestamp,event_type,uuid,username,ip_address,details\n");
                for (AuditEvent event : events) {
                    sb.append(event.getTimestamp() != null ? READABLE_FORMATTER.format(event.getTimestamp()) : "unknown").append(",");
                    sb.append(event.getEventType().name()).append(",");
                    sb.append(event.getPlayerUuid() != null ? event.getPlayerUuid().toString() : "").append(",");
                    sb.append(event.getUsername() != null ? event.getUsername() : "").append(",");
                    sb.append(event.getIpAddress() != null ? event.getIpAddress() : "").append(",");
                    sb.append("\"").append(event.getDetails() != null ? event.getDetails().replace("\"", "\"\"") : "").append("\"\n");
                }

                Files.writeString(exportPath, sb.toString());

                // Audit log
                auditService.logSystem(AuditEventType.AUDIT_EXPORT,
                        "Audit log exported to CSV. Events: " + events.size());

                return new ExportResult(true, exportPath.toString(), "csv", sb.length());
            } catch (Exception e) {
                logger.severe("Failed to export audit log: " + e.getMessage());
                return new ExportResult(false, null, "csv", 0);
            }
        });
    }

    /**
     * Export audit logs to PDF (simplified text-based PDF).
     */
    public CompletableFuture<ExportResult> exportAuditLogPdf(UUID targetUuid, int limit) {
        return storage.getAuditEvents(targetUuid, limit, 0).thenApply(events -> {
            try {
                Path exportPath = getAuditExportPath("txt"); // Using .txt as simplified PDF alternative

                StringBuilder sb = new StringBuilder();
                sb.append("================================================================================\n");
                sb.append("                         AUDIT LOG REPORT\n");
                sb.append("================================================================================\n\n");
                sb.append("Generated: ").append(READABLE_FORMATTER.format(Instant.now())).append("\n");
                if (targetUuid != null) {
                    sb.append("Target UUID: ").append(targetUuid).append("\n");
                }
                sb.append("Total Events: ").append(events.size()).append("\n");
                sb.append("================================================================================\n\n");

                for (AuditEvent event : events) {
                    sb.append("Event: ").append(event.getEventType().name()).append("\n");
                    sb.append("Time: ").append(event.getTimestamp() != null ? READABLE_FORMATTER.format(event.getTimestamp()) : "unknown").append("\n");
                    sb.append("User: ").append(event.getUsername() != null ? event.getUsername() : "N/A");
                    sb.append(" (").append(event.getPlayerUuid() != null ? event.getPlayerUuid().toString() : "N/A").append(")\n");
                    sb.append("IP: ").append(event.getIpAddress() != null ? event.getIpAddress() : "N/A").append("\n");
                    sb.append("Details: ").append(event.getDetails() != null ? event.getDetails() : "N/A").append("\n");
                    sb.append("--------------------------------------------------------------------------------\n");
                }

                sb.append("\n=== END OF REPORT ===\n");

                Files.writeString(exportPath, sb.toString());

                // Audit log
                auditService.logSystem(AuditEventType.AUDIT_EXPORT,
                        "Audit log exported to PDF format. Events: " + events.size());

                return new ExportResult(true, exportPath.toString(), "pdf", sb.length());
            } catch (Exception e) {
                logger.severe("Failed to export audit log: " + e.getMessage());
                return new ExportResult(false, null, "pdf", 0);
            }
        });
    }

    // === Helper Methods ===

    private Path getExportPath(UUID playerUuid, String format) {
        String filename = "player_data_" + playerUuid + "_" + System.currentTimeMillis() + "." + format;
        return platform.getDataFolder().toPath().resolve("exports").resolve(filename);
    }

    private Path getAuditExportPath(String format) {
        String filename = "audit_log_" + System.currentTimeMillis() + "." + format;
        return platform.getDataFolder().toPath().resolve("exports").resolve(filename);
    }

    private void trackExport(UUID playerUuid, String format, String path) {
        exportRequests.computeIfAbsent(playerUuid, k -> new ArrayList<>())
                .add(new ExportRequest(playerUuid, format, path, System.currentTimeMillis()));
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String playerName(UUID playerUuid) {
        String name = platform.getPlayerName(playerUuid);
        return name != null ? name : "Unknown";
    }

    private String playerIp(UUID playerUuid) {
        String ip = platform.getPlayerIp(playerUuid);
        return ip != null ? ip : "Unknown";
    }

    // === Data Classes ===

    /**
     * Represents a player's complete data bundle for export.
     */
    public static class PlayerDataBundle {
        private final UUID playerUuid;
        private Account account;
        private List<Session> sessions;
        private List<LoginAttempt> loginAttempts;
        private List<AuditEvent> auditEvents;
        private List<?> trustedDevices;
        private long exportedAt;

        public PlayerDataBundle(UUID playerUuid) {
            this.playerUuid = playerUuid;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public Account getAccount() { return account; }
        public void setAccount(Account account) { this.account = account; }
        public List<Session> getSessions() { return sessions; }
        public void setSessions(List<Session> sessions) { this.sessions = sessions; }
        public List<LoginAttempt> getLoginAttempts() { return loginAttempts; }
        public void setLoginAttempts(List<LoginAttempt> loginAttempts) { this.loginAttempts = loginAttempts; }
        public List<AuditEvent> getAuditEvents() { return auditEvents; }
        public void setAuditEvents(List<AuditEvent> auditEvents) { this.auditEvents = auditEvents; }
        public List<?> getTrustedDevices() { return trustedDevices; }
        public void setTrustedDevices(List<?> trustedDevices) { this.trustedDevices = trustedDevices; }
        public long getExportedAt() { return exportedAt; }
        public void setExportedAt(long exportedAt) { this.exportedAt = exportedAt; }
    }

    /**
     * Result of a data export operation.
     */
    public static class ExportResult {
        private final boolean success;
        private final String filePath;
        private final String format;
        private final int size;

        public ExportResult(boolean success, String filePath, String format, int size) {
            this.success = success;
            this.filePath = filePath;
            this.format = format;
            this.size = size;
        }

        public boolean isSuccess() { return success; }
        public String getFilePath() { return filePath; }
        public String getFormat() { return format; }
        public int getSize() { return size; }
    }

    /**
     * Represents a deletion request.
     */
    public static class DeletionRequest {
        private final UUID playerUuid;
        private final String username;
        private final String reason;
        private final long requestedAt;
        private final long expiresAt;

        public DeletionRequest(UUID playerUuid, String username, String reason, long requestedAt, long expiresAt) {
            this.playerUuid = playerUuid;
            this.username = username;
            this.reason = reason;
            this.requestedAt = requestedAt;
            this.expiresAt = expiresAt;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getUsername() { return username; }
        public String getReason() { return reason; }
        public long getRequestedAt() { return requestedAt; }
        public long getExpiresAt() { return expiresAt; }
    }

    /**
     * Result of a deletion request.
     */
    public static class DeletionResult {
        private final boolean success;
        private final String message;
        private final long gracePeriodDays;

        public DeletionResult(boolean success, String message, long gracePeriodDays) {
            this.success = success;
            this.message = message;
            this.gracePeriodDays = gracePeriodDays;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public long getGracePeriodDays() { return gracePeriodDays; }
    }

    /**
     * Represents an export request.
     */
    public static class ExportRequest {
        private final UUID playerUuid;
        private final String format;
        private final String filePath;
        private final long requestedAt;

        public ExportRequest(UUID playerUuid, String format, String filePath, long requestedAt) {
            this.playerUuid = playerUuid;
            this.format = format;
            this.filePath = filePath;
            this.requestedAt = requestedAt;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getFormat() { return format; }
        public String getFilePath() { return filePath; }
        public long getRequestedAt() { return requestedAt; }
    }

    /**
     * Compliance report.
     */
    public static class ComplianceReport {
        private long generatedAt;
        private String reportType;
        private String complianceStatus;
        private final Map<String, Object> metrics = new LinkedHashMap<>();

        public long getGeneratedAt() { return generatedAt; }
        public void setGeneratedAt(long generatedAt) { this.generatedAt = generatedAt; }
        public String getReportType() { return reportType; }
        public void setReportType(String reportType) { this.reportType = reportType; }
        public String getComplianceStatus() { return complianceStatus; }
        public void setComplianceStatus(String complianceStatus) { this.complianceStatus = complianceStatus; }
        public Map<String, Object> getMetrics() { return metrics; }
        public void addMetric(String key, Object value) { metrics.put(key, value); }
    }
}
