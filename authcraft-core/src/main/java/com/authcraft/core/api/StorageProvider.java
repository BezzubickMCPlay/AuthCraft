// com/authcraft/core/api/StorageProvider.java
package com.authcraft.core.api;

import com.authcraft.core.model.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Abstraction over all database operations.
 * All methods return CompletableFuture for async execution.
 */
public interface StorageProvider {

    // === Lifecycle ===
    CompletableFuture<Void> initialize();
    CompletableFuture<Void> shutdown();

    // === Accounts ===
    CompletableFuture<Optional<Account>> getAccount(UUID uuid);
    CompletableFuture<Optional<Account>> getAccountByName(String username);
    CompletableFuture<Void> saveAccount(Account account);
    CompletableFuture<Void> deleteAccount(UUID uuid);
    CompletableFuture<Integer> countAccountsByIp(String ip);
    CompletableFuture<List<Account>> getAllAccounts();

    // === Sessions ===
    CompletableFuture<Optional<Session>> getSession(UUID uuid);
    CompletableFuture<Optional<Session>> getSessionByToken(String token);
    CompletableFuture<Void> saveSession(Session session);
    CompletableFuture<Void> deleteSession(UUID uuid);
    CompletableFuture<Void> deleteExpiredSessions();
    CompletableFuture<Void> invalidateAllSessions(UUID uuid);

    // === Login Attempts ===
    CompletableFuture<Void> recordLoginAttempt(LoginAttempt attempt);
    CompletableFuture<List<LoginAttempt>> getRecentAttempts(
            UUID uuid, int limit);
    CompletableFuture<Integer> countRecentFailedAttempts(
            UUID uuid, long withinSeconds);
    CompletableFuture<Integer> countRecentAttemptsFromIp(
            String ip, long withinSeconds);

    // === Backup Codes ===
    CompletableFuture<Void> saveBackupCodes(
            UUID uuid, List<BackupCode> codes);
    CompletableFuture<List<BackupCode>> getBackupCodes(UUID uuid);
    CompletableFuture<Void> markBackupCodeUsed(long codeId);
    CompletableFuture<Void> deleteBackupCodes(UUID uuid);

    // === Audit Log ===
    CompletableFuture<Void> logEvent(AuditEvent event);
    CompletableFuture<List<AuditEvent>> getEvents(
        UUID uuid, int limit);
    CompletableFuture<List<AuditEvent>> getEventsByType(
        AuditEventType type, int limit);
    
    // === Web Dashboard Statistics ===
    CompletableFuture<Long> countAllAccounts();
    CompletableFuture<Long> countActiveSessions();
    CompletableFuture<Long> countLockedAccounts();
    CompletableFuture<Long> countTwoFactorEnabled();
    CompletableFuture<Long> countTwoFactorMethod(TwoFactorMethod method);
    CompletableFuture<Long> countLoginsSince(long timestamp);
    CompletableFuture<Long> countRegistrationsSince(long timestamp);
    CompletableFuture<Long> countFailedLoginsSince(long timestamp);
    CompletableFuture<Long> countRecentSecurityEvents(long withinSeconds);
    CompletableFuture<Long> countTwoFactorVerificationsSince(long timestamp);
    CompletableFuture<List<AuditEvent>> getAuditEventsSince(long timestamp);
    CompletableFuture<List<AuditEvent>> getAllAuditEvents();
    CompletableFuture<List<AuditEvent>> getAuditEventsForPlayer(UUID uuid);
    CompletableFuture<List<Map<String, Object>>> getLoginAttemptsBetween(long start, long end);
    CompletableFuture<List<Map<String, Object>>> getFailedLoginsSince(long timestamp);
    CompletableFuture<List<Map<String, Object>>> getLockedAccountsInfo();
    CompletableFuture<List<Session>> getSessionsForPlayer(UUID uuid);
    CompletableFuture<List<LoginAttempt>> getLoginAttemptsForPlayer(UUID uuid);
    CompletableFuture<List<Map<String, Object>>> getRegistrationsByDay(long since);
    CompletableFuture<List<Map<String, Object>>> getTwoFactorEnablesByDay(long since);

    // === Trusted Devices ===
    CompletableFuture<Void> saveTrustedDevice(TrustedDevice device);
    CompletableFuture<Optional<TrustedDevice>> getTrustedDevice(UUID playerUuid, String tokenHash);
    CompletableFuture<List<TrustedDevice>> getTrustedDevices(UUID playerUuid);
    CompletableFuture<Void> deleteTrustedDevice(UUID playerUuid, String tokenHash);
    CompletableFuture<Void> deleteAllTrustedDevices(UUID playerUuid);
    CompletableFuture<Void> deleteExpiredTrustedDevices();

    // === Compliance & Reporting ===
    CompletableFuture<Long> countAccountsWith2FA();
    CompletableFuture<Long> countTotalAccounts();
    CompletableFuture<Long> countRecentFailedLogins(long sinceTimestamp);
    CompletableFuture<List<Session>> getSessions(UUID playerUuid);
    CompletableFuture<List<LoginAttempt>> getLoginAttempts(UUID playerUuid);
    CompletableFuture<List<AuditEvent>> getAuditEvents(UUID playerUuid, int limit, int offset);
    CompletableFuture<Void> deleteAllSessions(UUID playerUuid);
    CompletableFuture<Void> deleteLoginAttempts(UUID playerUuid);
}