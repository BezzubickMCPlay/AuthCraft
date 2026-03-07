// com/authcraft/storage/AbstractSQLStorage.java
package com.authcraft.storage;

import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.*;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * Base SQL storage with HikariCP pooling and Caffeine caching.
 * Subclasses only override getJdbcUrl() and dialect-specific SQL.
 */
public abstract class AbstractSQLStorage implements StorageProvider {

    protected final AuthCraftConfig config;
    protected final Logger logger;
    protected HikariDataSource dataSource;
    protected final ExecutorService executor;

    // Caffeine caches
    protected final Cache<UUID, Account> accountCache;
    protected final Cache<String, Account> accountNameCache;
    protected final Cache<UUID, Session> sessionCache;

    public AbstractSQLStorage(AuthCraftConfig config, Logger logger) {
        this.config = config;
        this.logger = logger;
        this.executor = Executors.newFixedThreadPool(
                Math.max(2, config.getHikariMaxPoolSize() / 2)
        );

        this.accountCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(Duration.ofMinutes(30))
                .build();

        this.accountNameCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(Duration.ofMinutes(30))
                .build();

        this.sessionCache = Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(Duration.ofMinutes(60))
                .build();
    }

    protected abstract String getJdbcUrl();
    protected abstract String getDriverClassName();

    /**
     * Dialect-specific column type for auto-increment PK.
     */
    protected String autoIncrementType() {
        return "BIGINT AUTO_INCREMENT PRIMARY KEY";
    }

    /**
     * Dialect-specific timestamp current.
     */
    protected String currentTimestampDefault() {
        return "CURRENT_TIMESTAMP";
    }

    // =============================================
    // LIFECYCLE
    // =============================================

    @Override
    public CompletableFuture<Void> initialize() {
        return CompletableFuture.runAsync(() -> {
            try {
                HikariConfig hikariConfig = new HikariConfig();
                hikariConfig.setJdbcUrl(getJdbcUrl());
                hikariConfig.setDriverClassName(getDriverClassName());

                if (config.getDatabaseUsername() != null
                        && !config.getDatabaseUsername().isEmpty()) {
                    hikariConfig.setUsername(config.getDatabaseUsername());
                    hikariConfig.setPassword(config.getDatabasePassword());
                }

                hikariConfig.setMaximumPoolSize(config.getHikariMaxPoolSize());
                hikariConfig.setConnectionTimeout(
                        config.getHikariConnectionTimeout()
                );
                hikariConfig.setPoolName("AuthCraft-HikariPool");

                hikariConfig.addDataSourceProperty(
                        "cachePrepStmts", "true"
                );
                hikariConfig.addDataSourceProperty(
                        "prepStmtCacheSize", "250"
                );
                hikariConfig.addDataSourceProperty(
                        "prepStmtCacheSqlLimit", "2048"
                );

                dataSource = new HikariDataSource(hikariConfig);
                createTables();
                logger.info("[AuthCraft] Database initialized: "
                        + getJdbcUrl());
            } catch (Exception e) {
                throw new RuntimeException(
                        "Failed to initialize database", e
                );
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Void> shutdown() {
        return CompletableFuture.runAsync(() -> {
            accountCache.invalidateAll();
            accountNameCache.invalidateAll();
            sessionCache.invalidateAll();
            if (dataSource != null && !dataSource.isClosed()) {
                dataSource.close();
            }
            executor.shutdown();
            logger.info("[AuthCraft] Database connection closed");
        });
    }

    protected Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    // =============================================
    // TABLE CREATION
    // =============================================

    protected void createTables() throws SQLException {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS authcraft_accounts (
                    uuid VARCHAR(36) PRIMARY KEY,
                    username VARCHAR(64) NOT NULL,
                    normalized_username VARCHAR(64) NOT NULL,
                    password_hash VARCHAR(512) NOT NULL,
                    hash_algorithm VARCHAR(32) NOT NULL DEFAULT 'argon2id',
                    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
                    email VARCHAR(255),
                    role VARCHAR(64) NOT NULL DEFAULT 'guest',
                    two_factor_methods VARCHAR(128) DEFAULT '',
                    totp_secret VARCHAR(256),
                    telegram_chat_id VARCHAR(64),
                    vk_user_id VARCHAR(64),
                    failed_login_attempts INT DEFAULT 0,
                    locked_until BIGINT,
                    registration_ip VARCHAR(45),
                    last_login_ip VARCHAR(45),
                    last_login_date BIGINT,
                    created_at BIGINT NOT NULL,
                    updated_at BIGINT NOT NULL
                )
                """);

            // Migration: Add new columns if they don't exist (for existing databases)
            migrateToMultipleTwoFactorMethods(stmt);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS authcraft_sessions (
                    token VARCHAR(128) PRIMARY KEY,
                    player_uuid VARCHAR(36) NOT NULL,
                    ip_address VARCHAR(45) NOT NULL,
                    created_at BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    authenticated BOOLEAN DEFAULT TRUE,
                    two_factor_verified BOOLEAN DEFAULT FALSE
                )
            """);

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS authcraft_login_attempts (
                    id %s,
                    player_uuid VARCHAR(36),
                    ip_address VARCHAR(45) NOT NULL,
                    success BOOLEAN NOT NULL,
                    failure_reason VARCHAR(255),
                    timestamp BIGINT NOT NULL
                )
            """.formatted(autoIncrementType()));

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS authcraft_backup_codes (
                    id %s,
                    player_uuid VARCHAR(36) NOT NULL,
                    code_hash VARCHAR(128) NOT NULL,
                    used BOOLEAN DEFAULT FALSE
                )
            """.formatted(autoIncrementType()));

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS authcraft_audit_log (
                    id %s,
                    event_type VARCHAR(64) NOT NULL,
                    player_uuid VARCHAR(36),
                    username VARCHAR(64),
                    ip_address VARCHAR(45),
                    details TEXT,
                    timestamp BIGINT NOT NULL
                )
            """.formatted(autoIncrementType()));
    
            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS trusted_devices (
                    id %s,
                    player_uuid VARCHAR(36) NOT NULL,
                    token_hash VARCHAR(128) NOT NULL,
                    device_name VARCHAR(128),
                    ip_address VARCHAR(45) NOT NULL,
                    created_at BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    last_used_at BIGINT NOT NULL
                )
                """.formatted(autoIncrementType()));
    
            // Indexes
            tryExecute(stmt,
                    "CREATE INDEX IF NOT EXISTS idx_accounts_username "
                            + "ON authcraft_accounts(normalized_username)");
            tryExecute(stmt,
                    "CREATE INDEX IF NOT EXISTS idx_sessions_uuid "
                            + "ON authcraft_sessions(player_uuid)");
            tryExecute(stmt,
                    "CREATE INDEX IF NOT EXISTS idx_attempts_uuid "
                            + "ON authcraft_login_attempts(player_uuid, timestamp)");
            tryExecute(stmt,
                    "CREATE INDEX IF NOT EXISTS idx_attempts_ip "
                            + "ON authcraft_login_attempts(ip_address, timestamp)");
            tryExecute(stmt,
                    "CREATE INDEX IF NOT EXISTS idx_backup_uuid "
                            + "ON authcraft_backup_codes(player_uuid)");
            tryExecute(stmt,
                    "CREATE INDEX IF NOT EXISTS idx_audit_uuid "
                            + "ON authcraft_audit_log(player_uuid, timestamp)");
            tryExecute(stmt,
                "CREATE INDEX IF NOT EXISTS idx_audit_type "
                + "ON authcraft_audit_log(event_type, timestamp)");
            tryExecute(stmt,
                "CREATE INDEX IF NOT EXISTS idx_trusted_devices_uuid "
                + "ON trusted_devices(player_uuid)");
            tryExecute(stmt,
                "CREATE INDEX IF NOT EXISTS idx_trusted_devices_expires "
                + "ON trusted_devices(expires_at)");
            }
    }

    private void tryExecute(Statement stmt, String sql) {
        try {
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            // Index may already exist — ignore
        }
    }

    /**
     * Migrate from single two_factor_method to multiple two_factor_methods.
     * This handles existing databases that have the old schema.
     */
    private void migrateToMultipleTwoFactorMethods(Statement stmt) {
        try {
            // Check if old column exists
            var meta = stmt.getConnection().getMetaData();
            var columns = meta.getColumns(null, null, "authcraft_accounts", "two_factor_method");
            if (columns.next()) {
                // Old column exists - need to migrate
                logger.info("[AuthCraft] Migrating database schema for multiple 2FA methods...");

                // Create new columns if they don't exist
                tryExecute(stmt, "ALTER TABLE authcraft_accounts ADD COLUMN two_factor_methods VARCHAR(128) DEFAULT ''");
                tryExecute(stmt, "ALTER TABLE authcraft_accounts ADD COLUMN totp_secret VARCHAR(256)");

                // Migrate data: copy two_factor_method to two_factor_methods and two_factor_secret to totp_secret
                // For SQLite/PostgreSQL
                tryExecute(stmt, "UPDATE authcraft_accounts SET two_factor_methods = " +
                    "CASE WHEN two_factor_method != 'NONE' THEN two_factor_method ELSE '' END " +
                    "WHERE two_factor_methods = '' OR two_factor_methods IS NULL");
                tryExecute(stmt, "UPDATE authcraft_accounts SET totp_secret = two_factor_secret " +
                    "WHERE totp_secret IS NULL AND two_factor_secret IS NOT NULL");

                // Try to drop old columns (may fail on some DBs, that's OK)
                tryExecute(stmt, "ALTER TABLE authcraft_accounts DROP COLUMN two_factor_method");
                tryExecute(stmt, "ALTER TABLE authcraft_accounts DROP COLUMN two_factor_secret");

                logger.info("[AuthCraft] Database migration completed");
            }
        } catch (SQLException e) {
            // Migration may already be done or columns don't exist - that's OK
            logger.info("[AuthCraft] Migration check: " + e.getMessage());
        }
    }

    // =============================================
    // ACCOUNTS
    // =============================================

    @Override
    public CompletableFuture<Optional<Account>> getAccount(UUID uuid) {
        Account cached = accountCache.getIfPresent(uuid);
        if (cached != null) {
            return CompletableFuture.completedFuture(Optional.of(cached));
        }

        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_accounts WHERE uuid = ?")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        Account acc = mapAccount(rs);
                        accountCache.put(uuid, acc);
                        accountNameCache.put(
                                acc.getNormalizedUsername(), acc
                        );
                        return Optional.of(acc);
                    }
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getAccount: "
                        + e.getMessage());
            }
            return Optional.empty();
        }, executor);
    }

    @Override
    public CompletableFuture<Optional<Account>> getAccountByName(
            String username) {
        String normalized = username.toLowerCase();
        Account cached = accountNameCache.getIfPresent(normalized);
        if (cached != null) {
            return CompletableFuture.completedFuture(Optional.of(cached));
        }

        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_accounts "
                                 + "WHERE normalized_username = ?")) {
                ps.setString(1, normalized);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        Account acc = mapAccount(rs);
                        accountCache.put(acc.getUuid(), acc);
                        accountNameCache.put(normalized, acc);
                        return Optional.of(acc);
                    }
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getAccountByName: "
                        + e.getMessage());
            }
            return Optional.empty();
        }, executor);
    }

    @Override
    public CompletableFuture<Void> saveAccount(Account account) {
        return CompletableFuture.runAsync(() -> {
            String sql = """
                INSERT INTO authcraft_accounts
                (uuid, username, normalized_username, password_hash,
                hash_algorithm, status, email, role,
                two_factor_methods, totp_secret,
                telegram_chat_id, vk_user_id,
                failed_login_attempts, locked_until,
                registration_ip, last_login_ip,
                last_login_date, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(uuid) DO UPDATE SET
                username=excluded.username,
                normalized_username=excluded.normalized_username,
                password_hash=excluded.password_hash,
                hash_algorithm=excluded.hash_algorithm,
                status=excluded.status,
                email=excluded.email,
                role=excluded.role,
                two_factor_methods=excluded.two_factor_methods,
                totp_secret=excluded.totp_secret,
                telegram_chat_id=excluded.telegram_chat_id,
                vk_user_id=excluded.vk_user_id,
                failed_login_attempts=excluded.failed_login_attempts,
                locked_until=excluded.locked_until,
                registration_ip=excluded.registration_ip,
                last_login_ip=excluded.last_login_ip,
                last_login_date=excluded.last_login_date,
                updated_at=excluded.updated_at
                """;

            // MySQL uses different upsert syntax
            if ("mysql".equalsIgnoreCase(config.getDatabaseType())) {
                sql = getSaveAccountMySQL();
            }

            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                bindAccountParams(ps, account);
                ps.executeUpdate();

                // Update caches
                account.setUpdatedAt(Instant.now());
                accountCache.put(account.getUuid(), account);
                accountNameCache.put(
                    account.getNormalizedUsername(), account
                );
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error saveAccount: "
                    + e.getMessage());
                throw new RuntimeException(e);
            }
        }, executor);
    }

    private String getSaveAccountMySQL() {
        return """
            INSERT INTO authcraft_accounts
            (uuid, username, normalized_username, password_hash,
            hash_algorithm, status, email, role,
            two_factor_methods, totp_secret,
            telegram_chat_id, vk_user_id,
            failed_login_attempts, locked_until,
            registration_ip, last_login_ip,
            last_login_date, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE
            username=VALUES(username),
            normalized_username=VALUES(normalized_username),
            password_hash=VALUES(password_hash),
            hash_algorithm=VALUES(hash_algorithm),
            status=VALUES(status),
            email=VALUES(email),
            role=VALUES(role),
            two_factor_methods=VALUES(two_factor_methods),
            totp_secret=VALUES(totp_secret),
            telegram_chat_id=VALUES(telegram_chat_id),
            vk_user_id=VALUES(vk_user_id),
            failed_login_attempts=VALUES(failed_login_attempts),
            locked_until=VALUES(locked_until),
            registration_ip=VALUES(registration_ip),
            last_login_ip=VALUES(last_login_ip),
            last_login_date=VALUES(last_login_date),
            updated_at=VALUES(updated_at)
            """;
    }

    private void bindAccountParams(PreparedStatement ps, Account a)
    throws SQLException {
        ps.setString(1, a.getUuid().toString());
        ps.setString(2, a.getUsername());
        ps.setString(3, a.getNormalizedUsername() != null
            ? a.getNormalizedUsername() : a.getUsername().toLowerCase());
        ps.setString(4, a.getPasswordHash());
        ps.setString(5, a.getHashAlgorithm().getId());
        ps.setString(6, a.getStatus().name());
        ps.setString(7, a.getEmail());
        ps.setString(8, a.getRole());
        // Serialize enabled 2FA methods as comma-separated string
        ps.setString(9, serializeTwoFactorMethods(a.getEnabledTwoFactorMethods()));
        ps.setString(10, a.getTotpSecret());
        ps.setString(11, a.getTelegramChatId());
        ps.setString(12, a.getVkUserId());
        ps.setInt(13, a.getFailedLoginAttempts());
        ps.setObject(14, a.getLockedUntil() != null
            ? a.getLockedUntil().toEpochMilli() : null);
        ps.setString(15, a.getRegistrationIp());
        ps.setString(16, a.getLastLoginIp());
        ps.setObject(17, a.getLastLoginDate() != null
            ? a.getLastLoginDate().toEpochMilli() : null);
        ps.setLong(18, a.getCreatedAt().toEpochMilli());
        ps.setLong(19, Instant.now().toEpochMilli());
    }

    /**
     * Serialize a set of 2FA methods to a comma-separated string.
     */
    private String serializeTwoFactorMethods(java.util.Set<TwoFactorMethod> methods) {
        if (methods == null || methods.isEmpty()) {
            return "";
        }
        return methods.stream()
            .filter(m -> m != TwoFactorMethod.NONE)
            .map(Enum::name)
            .reduce((a, b) -> a + "," + b)
            .orElse("");
    }

    /**
     * Deserialize a comma-separated string to a set of 2FA methods.
     */
    private java.util.Set<TwoFactorMethod> deserializeTwoFactorMethods(String str) {
        java.util.Set<TwoFactorMethod> methods = java.util.EnumSet.noneOf(TwoFactorMethod.class);
        if (str == null || str.isEmpty()) {
            return methods;
        }
        for (String part : str.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                try {
                    methods.add(TwoFactorMethod.valueOf(trimmed.toUpperCase()));
                } catch (IllegalArgumentException ignored) {
                    // Invalid method name, skip
                }
            }
        }
        return methods;
    }

    @Override
    public CompletableFuture<Void> deleteAccount(UUID uuid) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "DELETE FROM authcraft_accounts WHERE uuid = ?")) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
                accountCache.invalidate(uuid);
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error deleteAccount: "
                        + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Integer> countAccountsByIp(String ip) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT COUNT(*) FROM authcraft_accounts "
                                 + "WHERE registration_ip = ?")) {
                ps.setString(1, ip);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) return rs.getInt(1);
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error countAccountsByIp: "
                        + e.getMessage());
            }
            return 0;
        }, executor);
    }

    @Override
    public CompletableFuture<List<Account>> getAllAccounts() {
        return CompletableFuture.supplyAsync(() -> {
            List<Account> accounts = new ArrayList<>();
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                         "SELECT * FROM authcraft_accounts")) {
                while (rs.next()) {
                    accounts.add(mapAccount(rs));
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getAllAccounts: "
                        + e.getMessage());
            }
            return accounts;
        }, executor);
    }

    // =============================================
    // SESSIONS
    // =============================================

    @Override
    public CompletableFuture<Optional<Session>> getSession(UUID uuid) {
        Session cached = sessionCache.getIfPresent(uuid);
        if (cached != null) {
            return CompletableFuture.completedFuture(Optional.of(cached));
        }

        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_sessions "
                                 + "WHERE player_uuid = ? AND authenticated = TRUE "
                                 + "ORDER BY created_at DESC LIMIT 1")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        Session session = mapSession(rs);
                        if (session.isValid()) {
                            sessionCache.put(uuid, session);
                            return Optional.of(session);
                        }
                    }
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getSession: "
                        + e.getMessage());
            }
            return Optional.empty();
        }, executor);
    }

    @Override
    public CompletableFuture<Optional<Session>> getSessionByToken(
            String token) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_sessions "
                                 + "WHERE token = ?")) {
                ps.setString(1, token);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return Optional.of(mapSession(rs));
                    }
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getSessionByToken: "
                        + e.getMessage());
            }
            return Optional.empty();
        }, executor);
    }

    @Override
    public CompletableFuture<Void> saveSession(Session session) {
        return CompletableFuture.runAsync(() -> {
            String sql;
            if ("mysql".equalsIgnoreCase(config.getDatabaseType())) {
                sql = """
                    INSERT INTO authcraft_sessions
                        (token, player_uuid, ip_address, created_at,
                         expires_at, authenticated, two_factor_verified)
                    VALUES (?,?,?,?,?,?,?)
                    ON DUPLICATE KEY UPDATE
                        ip_address=VALUES(ip_address),
                        expires_at=VALUES(expires_at),
                        authenticated=VALUES(authenticated),
                        two_factor_verified=VALUES(two_factor_verified)
                """;
            } else {
                sql = """
                    INSERT INTO authcraft_sessions
                        (token, player_uuid, ip_address, created_at,
                         expires_at, authenticated, two_factor_verified)
                    VALUES (?,?,?,?,?,?,?)
                    ON CONFLICT(token) DO UPDATE SET
                        ip_address=excluded.ip_address,
                        expires_at=excluded.expires_at,
                        authenticated=excluded.authenticated,
                        two_factor_verified=excluded.two_factor_verified
                """;
            }

            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, session.getToken());
                ps.setString(2, session.getPlayerUuid().toString());
                ps.setString(3, session.getIpAddress());
                ps.setLong(4, session.getCreatedAt().toEpochMilli());
                ps.setLong(5, session.getExpiresAt().toEpochMilli());
                ps.setBoolean(6, session.isAuthenticated());
                ps.setBoolean(7, session.isTwoFactorVerified());
                ps.executeUpdate();

                sessionCache.put(session.getPlayerUuid(), session);
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error saveSession: "
                        + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Void> deleteSession(UUID uuid) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "DELETE FROM authcraft_sessions "
                                 + "WHERE player_uuid = ?")) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
                sessionCache.invalidate(uuid);
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error deleteSession: "
                        + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Void> deleteExpiredSessions() {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "DELETE FROM authcraft_sessions "
                                 + "WHERE expires_at < ?")) {
                ps.setLong(1, Instant.now().toEpochMilli());
                int deleted = ps.executeUpdate();
                if (deleted > 0) {
                    logger.info("[AuthCraft] Cleaned " + deleted
                            + " expired sessions");
                }
            } catch (SQLException e) {
                logger.warning(
                        "[AuthCraft] DB error deleteExpiredSessions: "
                                + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Void> invalidateAllSessions(UUID uuid) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "UPDATE authcraft_sessions "
                                 + "SET authenticated = FALSE "
                                 + "WHERE player_uuid = ?")) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
                sessionCache.invalidate(uuid);
            } catch (SQLException e) {
                logger.warning(
                        "[AuthCraft] DB error invalidateAllSessions: "
                                + e.getMessage());
            }
        }, executor);
    }

    // =============================================
    // LOGIN ATTEMPTS
    // =============================================

    @Override
    public CompletableFuture<Void> recordLoginAttempt(
            LoginAttempt attempt) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "INSERT INTO authcraft_login_attempts "
                                 + "(player_uuid, ip_address, success, "
                                 + "failure_reason, timestamp) "
                                 + "VALUES (?,?,?,?,?)")) {
                ps.setString(1, attempt.getPlayerUuid() != null
                        ? attempt.getPlayerUuid().toString() : null);
                ps.setString(2, attempt.getIpAddress());
                ps.setBoolean(3, attempt.isSuccess());
                ps.setString(4, attempt.getFailureReason());
                ps.setLong(5, attempt.getTimestamp().toEpochMilli());
                ps.executeUpdate();
            } catch (SQLException e) {
                logger.warning(
                        "[AuthCraft] DB error recordLoginAttempt: "
                                + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<List<LoginAttempt>> getRecentAttempts(
            UUID uuid, int limit) {
        return CompletableFuture.supplyAsync(() -> {
            List<LoginAttempt> attempts = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_login_attempts "
                                 + "WHERE player_uuid = ? "
                                 + "ORDER BY timestamp DESC LIMIT ?")) {
                ps.setString(1, uuid.toString());
                ps.setInt(2, limit);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        attempts.add(mapLoginAttempt(rs));
                    }
                }
            } catch (SQLException e) {
                logger.warning(
                        "[AuthCraft] DB error getRecentAttempts: "
                                + e.getMessage());
            }
            return attempts;
        }, executor);
    }

    @Override
    public CompletableFuture<Integer> countRecentFailedAttempts(
            UUID uuid, long withinSeconds) {
        return CompletableFuture.supplyAsync(() -> {
            long since = Instant.now()
                    .minusSeconds(withinSeconds).toEpochMilli();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT COUNT(*) FROM authcraft_login_attempts "
                                 + "WHERE player_uuid = ? AND success = FALSE "
                                 + "AND timestamp > ?")) {
                ps.setString(1, uuid.toString());
                ps.setLong(2, since);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) return rs.getInt(1);
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error count failed: "
                        + e.getMessage());
            }
            return 0;
        }, executor);
    }

    @Override
    public CompletableFuture<Integer> countRecentAttemptsFromIp(
            String ip, long withinSeconds) {
        return CompletableFuture.supplyAsync(() -> {
            long since = Instant.now()
                    .minusSeconds(withinSeconds).toEpochMilli();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT COUNT(*) FROM authcraft_login_attempts "
                                 + "WHERE ip_address = ? AND timestamp > ?")) {
                ps.setString(1, ip);
                ps.setLong(2, since);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) return rs.getInt(1);
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error count ip: "
                        + e.getMessage());
            }
            return 0;
        }, executor);
    }

    // =============================================
    // BACKUP CODES
    // =============================================

    @Override
    public CompletableFuture<Void> saveBackupCodes(
            UUID uuid, List<BackupCode> codes) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "INSERT INTO authcraft_backup_codes "
                                 + "(player_uuid, code_hash, used) "
                                 + "VALUES (?,?,?)")) {
                for (BackupCode code : codes) {
                    ps.setString(1, uuid.toString());
                    ps.setString(2, code.getCodeHash());
                    ps.setBoolean(3, code.isUsed());
                    ps.addBatch();
                }
                ps.executeBatch();
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error saveBackupCodes: "
                        + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<List<BackupCode>> getBackupCodes(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            List<BackupCode> codes = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_backup_codes "
                                 + "WHERE player_uuid = ?")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        BackupCode code = new BackupCode();
                        code.setId(rs.getLong("id"));
                        code.setPlayerUuid(UUID.fromString(
                                rs.getString("player_uuid")));
                        code.setCodeHash(rs.getString("code_hash"));
                        code.setUsed(rs.getBoolean("used"));
                        codes.add(code);
                    }
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getBackupCodes: "
                        + e.getMessage());
            }
            return codes;
        }, executor);
    }

    @Override
    public CompletableFuture<Void> markBackupCodeUsed(long codeId) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "UPDATE authcraft_backup_codes "
                                 + "SET used = TRUE WHERE id = ?")) {
                ps.setLong(1, codeId);
                ps.executeUpdate();
            } catch (SQLException e) {
                logger.warning(
                        "[AuthCraft] DB error markBackupCodeUsed: "
                                + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<Void> deleteBackupCodes(UUID uuid) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "DELETE FROM authcraft_backup_codes "
                                 + "WHERE player_uuid = ?")) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
            } catch (SQLException e) {
                logger.warning(
                        "[AuthCraft] DB error deleteBackupCodes: "
                                + e.getMessage());
            }
        }, executor);
    }

    // =============================================
    // AUDIT LOG
    // =============================================

    @Override
    public CompletableFuture<Void> logEvent(AuditEvent event) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "INSERT INTO authcraft_audit_log "
                                 + "(event_type, player_uuid, username, "
                                 + "ip_address, details, timestamp) "
                                 + "VALUES (?,?,?,?,?,?)")) {
                ps.setString(1, event.getEventType().name());
                ps.setString(2, event.getPlayerUuid() != null
                        ? event.getPlayerUuid().toString() : null);
                ps.setString(3, event.getUsername());
                ps.setString(4, event.getIpAddress());
                ps.setString(5, event.getDetails());
                ps.setLong(6, event.getTimestamp().toEpochMilli());
                ps.executeUpdate();
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error logEvent: "
                        + e.getMessage());
            }
        }, executor);
    }

    @Override
    public CompletableFuture<List<AuditEvent>> getEvents(
            UUID uuid, int limit) {
        return CompletableFuture.supplyAsync(() -> {
            List<AuditEvent> events = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_audit_log "
                                 + "WHERE player_uuid = ? "
                                 + "ORDER BY timestamp DESC LIMIT ?")) {
                ps.setString(1, uuid.toString());
                ps.setInt(2, limit);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        events.add(mapAuditEvent(rs));
                    }
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getEvents: "
                        + e.getMessage());
            }
            return events;
        }, executor);
    }

    @Override
    public CompletableFuture<List<AuditEvent>> getEventsByType(
            AuditEventType type, int limit) {
        return CompletableFuture.supplyAsync(() -> {
            List<AuditEvent> events = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM authcraft_audit_log "
                                 + "WHERE event_type = ? "
                                 + "ORDER BY timestamp DESC LIMIT ?")) {
                ps.setString(1, type.name());
                ps.setInt(2, limit);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        events.add(mapAuditEvent(rs));
                    }
                }
            } catch (SQLException e) {
                logger.warning("[AuthCraft] DB error getEventsByType: "
                        + e.getMessage());
            }
            return events;
        }, executor);
    }

    // =============================================
    // RESULT SET MAPPERS
    // =============================================

    protected Account mapAccount(ResultSet rs) throws SQLException {
        Account acc = new Account();
        acc.setUuid(UUID.fromString(rs.getString("uuid")));
        acc.setUsername(rs.getString("username"));
        acc.setNormalizedUsername(rs.getString("normalized_username"));
        acc.setPasswordHash(rs.getString("password_hash"));
        acc.setHashAlgorithm(
            HashAlgorithm.fromId(rs.getString("hash_algorithm"))
        );
        acc.setStatus(AccountStatus.valueOf(rs.getString("status")));
        acc.setEmail(rs.getString("email"));
        acc.setRole(rs.getString("role"));

        // Handle both old (single method) and new (multiple methods) schema
        String methodsStr = null;
        try {
            methodsStr = rs.getString("two_factor_methods");
        } catch (SQLException e) {
            // Column doesn't exist, try old column
        }

        if (methodsStr != null) {
            // New schema - multiple methods
            acc.setEnabledTwoFactorMethods(deserializeTwoFactorMethods(methodsStr));
        } else {
            // Old schema - single method (for backwards compatibility during migration)
            try {
                String oldMethod = rs.getString("two_factor_method");
                if (oldMethod != null && !oldMethod.equals("NONE")) {
                    acc.enableTwoFactorMethod(TwoFactorMethod.valueOf(oldMethod));
                }
            } catch (SQLException ignored) {
                // Column doesn't exist
            }
        }

        // Handle both old and new secret column names
        String totpSecret = null;
        try {
            totpSecret = rs.getString("totp_secret");
        } catch (SQLException e) {
            // Column doesn't exist, try old column
        }
        if (totpSecret != null) {
            acc.setTotpSecret(totpSecret);
        } else {
            try {
                acc.setTotpSecret(rs.getString("two_factor_secret"));
            } catch (SQLException ignored) {
                // Column doesn't exist
            }
        }

        acc.setTelegramChatId(rs.getString("telegram_chat_id"));
        acc.setVkUserId(rs.getString("vk_user_id"));
        acc.setFailedLoginAttempts(rs.getInt("failed_login_attempts"));

        long lockedUntilMs = rs.getLong("locked_until");
        acc.setLockedUntil(lockedUntilMs > 0
                ? Instant.ofEpochMilli(lockedUntilMs) : null);
        acc.setRegistrationIp(rs.getString("registration_ip"));
        acc.setLastLoginIp(rs.getString("last_login_ip"));

        long lastLoginMs = rs.getLong("last_login_date");
        acc.setLastLoginDate(lastLoginMs > 0
                ? Instant.ofEpochMilli(lastLoginMs) : null);
        acc.setCreatedAt(
                Instant.ofEpochMilli(rs.getLong("created_at"))
        );
        acc.setUpdatedAt(
                Instant.ofEpochMilli(rs.getLong("updated_at"))
        );
        return acc;
    }

    protected Session mapSession(ResultSet rs) throws SQLException {
        Session session = new Session();
        session.setToken(rs.getString("token"));
        session.setPlayerUuid(
                UUID.fromString(rs.getString("player_uuid"))
        );
        session.setIpAddress(rs.getString("ip_address"));
        session.setCreatedAt(
                Instant.ofEpochMilli(rs.getLong("created_at"))
        );
        session.setExpiresAt(
                Instant.ofEpochMilli(rs.getLong("expires_at"))
        );
        session.setAuthenticated(rs.getBoolean("authenticated"));
        session.setTwoFactorVerified(
                rs.getBoolean("two_factor_verified")
        );
        return session;
    }

    protected LoginAttempt mapLoginAttempt(ResultSet rs)
            throws SQLException {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setId(rs.getLong("id"));
        String uuidStr = rs.getString("player_uuid");
        attempt.setPlayerUuid(
                uuidStr != null ? UUID.fromString(uuidStr) : null
        );
        attempt.setIpAddress(rs.getString("ip_address"));
        attempt.setSuccess(rs.getBoolean("success"));
        attempt.setFailureReason(rs.getString("failure_reason"));
        attempt.setTimestamp(
                Instant.ofEpochMilli(rs.getLong("timestamp"))
        );
        return attempt;
    }

    protected AuditEvent mapAuditEvent(ResultSet rs)
            throws SQLException {
        AuditEvent event = new AuditEvent();
        event.setId(rs.getLong("id"));
        event.setEventType(
            AuditEventType.valueOf(rs.getString("event_type"))
        );
        String uuidStr = rs.getString("player_uuid");
        event.setPlayerUuid(
            uuidStr != null ? UUID.fromString(uuidStr) : null
        );
        event.setUsername(rs.getString("username"));
        event.setIpAddress(rs.getString("ip_address"));
        event.setDetails(rs.getString("details"));
        event.setTimestamp(
            Instant.ofEpochMilli(rs.getLong("timestamp"))
        );
        return event;
    }
    
    // === Web Dashboard Statistics ===
    
    @Override
    public CompletableFuture<Long> countAllAccounts() {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM accounts")) {
                return rs.next() ? rs.getLong(1) : 0L;
            } catch (SQLException e) {
                logger.severe("Error counting accounts: " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countActiveSessions() {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                     "SELECT COUNT(*) FROM sessions WHERE expires_at > " + System.currentTimeMillis())) {
                return rs.next() ? rs.getLong(1) : 0L;
            } catch (SQLException e) {
                logger.severe("Error counting active sessions: " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countLockedAccounts() {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                     "SELECT COUNT(*) FROM accounts WHERE locked_until > " + System.currentTimeMillis())) {
                return rs.next() ? rs.getLong(1) : 0L;
            } catch (SQLException e) {
                logger.severe("Error counting locked accounts: " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countTwoFactorEnabled() {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                     "SELECT COUNT(*) FROM accounts WHERE two_factor_method IS NOT NULL AND two_factor_method != 'NONE'")) {
                return rs.next() ? rs.getLong(1) : 0L;
            } catch (SQLException e) {
                logger.severe("Error counting 2FA enabled accounts: " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countTwoFactorMethod(TwoFactorMethod method) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM accounts WHERE two_factor_methods LIKE ?")) {
                ps.setString(1, "%" + method.name() + "%");
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getLong(1) : 0L;
                }
            } catch (SQLException e) {
                logger.severe("Error counting 2FA method: " + method + ": " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countLoginsSince(long timestamp) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM login_attempts WHERE success = 1 AND timestamp >= ?")) {
                ps.setLong(1, timestamp);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getLong(1) : 0L;
                }
            } catch (SQLException e) {
                logger.severe("Error counting logins since " + timestamp + ": " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countRegistrationsSince(long timestamp) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM accounts WHERE created_at >= ?")) {
                ps.setLong(1, timestamp);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getLong(1) : 0L;
                }
            } catch (SQLException e) {
                logger.severe("Error counting registrations since " + timestamp + ": " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countFailedLoginsSince(long timestamp) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM login_attempts WHERE success = 0 AND timestamp >= ?")) {
                ps.setLong(1, timestamp);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getLong(1) : 0L;
                }
            } catch (SQLException e) {
                logger.severe("Error counting failed logins since " + timestamp + ": " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countRecentSecurityEvents(long withinSeconds) {
        long since = System.currentTimeMillis() - (withinSeconds * 1000);
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND event_type IN ('LOGIN_FAILED', 'ACCOUNT_LOCKED', 'SUSPICIOUS_LOGIN')")) {
                ps.setLong(1, since);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getLong(1) : 0L;
                }
            } catch (SQLException e) {
                logger.severe("Error counting security events: " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<Long> countTwoFactorVerificationsSince(long timestamp) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT COUNT(*) FROM audit_log WHERE event_type = 'TWO_FACTOR_SUCCESS' AND timestamp >= ?")) {
                ps.setLong(1, timestamp);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getLong(1) : 0L;
                }
            } catch (SQLException e) {
                logger.severe("Error counting 2FA verifications: " + e.getMessage());
                return 0L;
            }
        });
    }
    
    @Override
    public CompletableFuture<List<AuditEvent>> getAuditEventsSince(long timestamp) {
        return CompletableFuture.supplyAsync(() -> {
            List<AuditEvent> events = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT * FROM audit_log WHERE timestamp >= ? ORDER BY timestamp DESC")) {
                ps.setLong(1, timestamp);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        events.add(mapAuditEvent(rs));
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting audit events since " + timestamp + ": " + e.getMessage());
            }
            return events;
        });
    }
    
    @Override
    public CompletableFuture<List<AuditEvent>> getAllAuditEvents() {
        return CompletableFuture.supplyAsync(() -> {
            List<AuditEvent> events = new ArrayList<>();
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 1000")) {
                while (rs.next()) {
                    events.add(mapAuditEvent(rs));
                }
            } catch (SQLException e) {
                logger.severe("Error getting all audit events: " + e.getMessage());
            }
            return events;
        });
    }
    
    @Override
    public CompletableFuture<List<AuditEvent>> getAuditEventsForPlayer(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            List<AuditEvent> events = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT * FROM audit_log WHERE player_uuid = ? ORDER BY timestamp DESC LIMIT 100")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        events.add(mapAuditEvent(rs));
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting audit events for player: " + uuid + ": " + e.getMessage());
            }
            return events;
        });
    }
    
    @Override
    public CompletableFuture<List<Map<String, Object>>> getLoginAttemptsBetween(long start, long end) {
        return CompletableFuture.supplyAsync(() -> {
            List<Map<String, Object>> attempts = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT timestamp, success FROM login_attempts WHERE timestamp >= ? AND timestamp <= ?")) {
                ps.setLong(1, start);
                ps.setLong(2, end);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> attempt = new HashMap<>();
                        attempt.put("timestamp", rs.getLong("timestamp"));
                        attempt.put("success", rs.getBoolean("success"));
                        attempts.add(attempt);
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting login attempts between " + start + " and " + end + ": " + e.getMessage());
            }
            return attempts;
        });
    }
    
    @Override
    public CompletableFuture<List<Map<String, Object>>> getFailedLoginsSince(long timestamp) {
        return CompletableFuture.supplyAsync(() -> {
            List<Map<String, Object>> attempts = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT ip_address, COUNT(*) as count FROM login_attempts WHERE success = 0 AND timestamp >= ? GROUP BY ip_address")) {
                ps.setLong(1, timestamp);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> attempt = new HashMap<>();
                        attempt.put("ip", rs.getString("ip_address"));
                        attempt.put("count", rs.getLong("count"));
                        attempts.add(attempt);
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting failed logins since " + timestamp + ": " + e.getMessage());
            }
            return attempts;
        });
    }
    
    @Override
    public CompletableFuture<List<Map<String, Object>>> getLockedAccountsInfo() {
        return CompletableFuture.supplyAsync(() -> {
            List<Map<String, Object>> accounts = new ArrayList<>();
            try (Connection conn = getConnection();
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                     "SELECT uuid, username, last_login_ip, locked_until FROM accounts WHERE locked_until > " + System.currentTimeMillis())) {
                while (rs.next()) {
                    Map<String, Object> account = new HashMap<>();
                    account.put("uuid", UUID.fromString(rs.getString("uuid")));
                    account.put("username", rs.getString("username"));
                    account.put("lastIp", rs.getString("last_login_ip"));
                    account.put("lockUntil", rs.getLong("locked_until"));
                    accounts.add(account);
                }
            } catch (SQLException e) {
                logger.severe("Error getting locked accounts info: " + e.getMessage());
            }
            return accounts;
        });
    }
    
    @Override
    public CompletableFuture<List<Session>> getSessionsForPlayer(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            List<Session> sessions = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT * FROM sessions WHERE player_uuid = ? ORDER BY created_at DESC")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        sessions.add(mapSession(rs));
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting sessions for player: " + uuid + ": " + e.getMessage());
            }
            return sessions;
        });
    }
    
    @Override
    public CompletableFuture<List<LoginAttempt>> getLoginAttemptsForPlayer(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            List<LoginAttempt> attempts = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT * FROM login_attempts WHERE player_uuid = ? ORDER BY timestamp DESC LIMIT 50")) {
                ps.setString(1, uuid.toString());
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        attempts.add(mapLoginAttempt(rs));
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting login attempts for player: " + uuid + ": " + e.getMessage());
            }
            return attempts;
        });
    }
    
    @Override
    public CompletableFuture<List<Map<String, Object>>> getRegistrationsByDay(long since) {
        return CompletableFuture.supplyAsync(() -> {
            List<Map<String, Object>> stats = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT DATE(created_at / 86400000) as day, COUNT(*) as count FROM accounts WHERE created_at >= ? GROUP BY day ORDER BY day")) {
                ps.setLong(1, since);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> stat = new HashMap<>();
                        stat.put("day", rs.getString("day"));
                        stat.put("count", rs.getLong("count"));
                        stats.add(stat);
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting registrations by day: " + e.getMessage());
            }
            return stats;
        });
    }

    @Override
    public CompletableFuture<List<Map<String, Object>>> getTwoFactorEnablesByDay(long since) {
        return CompletableFuture.supplyAsync(() -> {
            List<Map<String, Object>> stats = new ArrayList<>();
            try (Connection conn = getConnection();
                 PreparedStatement ps = conn.prepareStatement(
                     "SELECT DATE(timestamp / 86400000) as day, COUNT(*) as count FROM audit_log WHERE event_type = 'TWO_FACTOR_ENABLED' AND timestamp >= ? GROUP BY day ORDER BY day")) {
                ps.setLong(1, since);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> stat = new HashMap<>();
                        stat.put("day", rs.getString("day"));
                        stat.put("count", rs.getLong("count"));
                        stats.add(stat);
                    }
                }
            } catch (SQLException e) {
                logger.severe("Error getting 2FA enables by day: " + e.getMessage());
            }
            return stats;
        });
    }

    // === Trusted Devices ===
    
        @Override
        public CompletableFuture<Void> saveTrustedDevice(TrustedDevice device) {
            return CompletableFuture.runAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                         "INSERT OR REPLACE INTO trusted_devices " +
                         "(player_uuid, token_hash, device_name, ip_address, created_at, expires_at, last_used_at) " +
                         "VALUES (?, ?, ?, ?, ?, ?, ?)")) {
                    ps.setString(1, device.getPlayerUuid().toString());
                    ps.setString(2, device.getTokenHash());
                    ps.setString(3, device.getDeviceName());
                    ps.setString(4, device.getIpAddress());
                    ps.setLong(5, device.getCreatedAt().toEpochMilli());
                    ps.setLong(6, device.getExpiresAt().toEpochMilli());
                    ps.setLong(7, device.getLastUsedAt().toEpochMilli());
                    ps.executeUpdate();
                } catch (SQLException e) {
                    logger.severe("Error saving trusted device: " + e.getMessage());
                }
            });
        }
    
        @Override
        public CompletableFuture<Optional<TrustedDevice>> getTrustedDevice(UUID playerUuid, String tokenHash) {
            return CompletableFuture.supplyAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM trusted_devices WHERE player_uuid = ? AND token_hash = ?")) {
                    ps.setString(1, playerUuid.toString());
                    ps.setString(2, tokenHash);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            return Optional.of(mapTrustedDevice(rs));
                        }
                    }
                } catch (SQLException e) {
                    logger.severe("Error getting trusted device: " + e.getMessage());
                }
                return Optional.empty();
            });
        }
    
        @Override
        public CompletableFuture<List<TrustedDevice>> getTrustedDevices(UUID playerUuid) {
            return CompletableFuture.supplyAsync(() -> {
                List<TrustedDevice> devices = new ArrayList<>();
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                         "SELECT * FROM trusted_devices WHERE player_uuid = ? ORDER BY last_used_at DESC")) {
                    ps.setString(1, playerUuid.toString());
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            devices.add(mapTrustedDevice(rs));
                        }
                    }
                } catch (SQLException e) {
                    logger.severe("Error getting trusted devices: " + e.getMessage());
                }
                return devices;
            });
        }
    
        @Override
        public CompletableFuture<Void> deleteTrustedDevice(UUID playerUuid, String tokenHash) {
            return CompletableFuture.runAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                         "DELETE FROM trusted_devices WHERE player_uuid = ? AND token_hash = ?")) {
                    ps.setString(1, playerUuid.toString());
                    ps.setString(2, tokenHash);
                    ps.executeUpdate();
                } catch (SQLException e) {
                    logger.severe("Error deleting trusted device: " + e.getMessage());
                }
            });
        }
    
        @Override
        public CompletableFuture<Void> deleteAllTrustedDevices(UUID playerUuid) {
            return CompletableFuture.runAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                         "DELETE FROM trusted_devices WHERE player_uuid = ?")) {
                    ps.setString(1, playerUuid.toString());
                    ps.executeUpdate();
                } catch (SQLException e) {
                    logger.severe("Error deleting all trusted devices: " + e.getMessage());
                }
            });
        }
    
        @Override
        public CompletableFuture<Void> deleteExpiredTrustedDevices() {
            return CompletableFuture.runAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                         "DELETE FROM trusted_devices WHERE expires_at < ?")) {
                    ps.setLong(1, System.currentTimeMillis());
                    ps.executeUpdate();
                } catch (SQLException e) {
                    logger.severe("Error deleting expired trusted devices: " + e.getMessage());
                }
            });
        }
    
        private TrustedDevice mapTrustedDevice(ResultSet rs) throws SQLException {
            return new TrustedDevice(
                UUID.fromString(rs.getString("player_uuid")),
                rs.getString("token_hash"),
                rs.getString("device_name"),
                rs.getString("ip_address"),
                Instant.ofEpochMilli(rs.getLong("created_at")),
                Instant.ofEpochMilli(rs.getLong("expires_at")),
                Instant.ofEpochMilli(rs.getLong("last_used_at"))
            );
        }
    
        // === Compliance & Reporting Methods ===
    
        @Override
        public CompletableFuture<Long> countAccountsWith2FA() {
            return CompletableFuture.supplyAsync(() -> {
                try (Connection conn = getConnection();
                     Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(
                             "SELECT COUNT(*) FROM accounts WHERE two_factor_methods IS NOT NULL AND two_factor_methods != '[]' AND two_factor_methods != ''")) {
                    if (rs.next()) {
                        return rs.getLong(1);
                    }
                    return 0L;
                } catch (SQLException e) {
                    logger.severe("Error counting accounts with 2FA: " + e.getMessage());
                    return 0L;
                }
            });
        }
    
        @Override
        public CompletableFuture<Long> countTotalAccounts() {
            return CompletableFuture.supplyAsync(() -> {
                try (Connection conn = getConnection();
                     Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM accounts")) {
                    if (rs.next()) {
                        return rs.getLong(1);
                    }
                    return 0L;
                } catch (SQLException e) {
                    logger.severe("Error counting total accounts: " + e.getMessage());
                    return 0L;
                }
            });
        }
    
        @Override
        public CompletableFuture<Long> countRecentFailedLogins(long sinceTimestamp) {
            return CompletableFuture.supplyAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                             "SELECT COUNT(*) FROM login_attempts WHERE success = 0 AND timestamp >= ?")) {
                    ps.setLong(1, sinceTimestamp);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            return rs.getLong(1);
                        }
                        return 0L;
                    }
                } catch (SQLException e) {
                    logger.severe("Error counting recent failed logins: " + e.getMessage());
                    return 0L;
                }
            });
        }
    
        @Override
        public CompletableFuture<List<Session>> getSessions(UUID playerUuid) {
            return CompletableFuture.supplyAsync(() -> {
                List<Session> sessions = new ArrayList<>();
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                             "SELECT * FROM sessions WHERE player_uuid = ? ORDER BY created_at DESC")) {
                    ps.setString(1, playerUuid.toString());
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            sessions.add(mapSession(rs));
                        }
                    }
                } catch (SQLException e) {
                    logger.severe("Error getting sessions: " + e.getMessage());
                }
                return sessions;
            });
        }
    
        @Override
        public CompletableFuture<List<LoginAttempt>> getLoginAttempts(UUID playerUuid) {
            return CompletableFuture.supplyAsync(() -> {
                List<LoginAttempt> attempts = new ArrayList<>();
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                             "SELECT * FROM login_attempts WHERE player_uuid = ? ORDER BY timestamp DESC LIMIT 100")) {
                    ps.setString(1, playerUuid.toString());
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            attempts.add(mapLoginAttempt(rs));
                        }
                    }
                } catch (SQLException e) {
                    logger.severe("Error getting login attempts: " + e.getMessage());
                }
                return attempts;
            });
        }
    
        @Override
        public CompletableFuture<List<AuditEvent>> getAuditEvents(UUID playerUuid, int limit, int offset) {
            return CompletableFuture.supplyAsync(() -> {
                List<AuditEvent> events = new ArrayList<>();
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                             "SELECT * FROM audit_log WHERE uuid = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?")) {
                    ps.setString(1, playerUuid.toString());
                    ps.setInt(2, limit);
                    ps.setInt(3, offset);
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            events.add(mapAuditEvent(rs));
                        }
                    }
                } catch (SQLException e) {
                    logger.severe("Error getting audit events: " + e.getMessage());
                }
                return events;
            });
        }
    
        @Override
        public CompletableFuture<Void> deleteAllSessions(UUID playerUuid) {
            return CompletableFuture.runAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                             "DELETE FROM sessions WHERE player_uuid = ?")) {
                    ps.setString(1, playerUuid.toString());
                    ps.executeUpdate();
                } catch (SQLException e) {
                    logger.severe("Error deleting all sessions: " + e.getMessage());
                }
            });
        }
    
        @Override
        public CompletableFuture<Void> deleteLoginAttempts(UUID playerUuid) {
            return CompletableFuture.runAsync(() -> {
                try (Connection conn = getConnection();
                     PreparedStatement ps = conn.prepareStatement(
                             "DELETE FROM login_attempts WHERE player_uuid = ?")) {
                    ps.setString(1, playerUuid.toString());
                    ps.executeUpdate();
                } catch (SQLException e) {
                    logger.severe("Error deleting login attempts: " + e.getMessage());
                }
            });
        }
    }