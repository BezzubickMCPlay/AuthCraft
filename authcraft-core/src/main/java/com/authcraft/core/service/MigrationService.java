// com/authcraft/core/service/MigrationService.java
package com.authcraft.core.service;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.*;

import java.io.*;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;

/**
 * Migrates data from AuthMe, xAuth, CrazyLogin into AuthCraft.
 */
public class MigrationService {

    private final AuthCraftCore core;
    private final StorageProvider storage;
    private final Logger logger;

    public MigrationService(AuthCraftCore core) {
        this.core = core;
        this.storage = core.getStorage();
        this.logger = core.getPlatform().getLogger();
    }

    /**
     * Migrate from AuthMe SQLite database.
     */
    public int migrateFromAuthMeSQLite(File dbFile) {
        if (!dbFile.exists()) {
            logger.warning("[Migration] AuthMe DB not found: " + dbFile.getAbsolutePath());
            return 0;
        }

        int count = 0;
        String url = "jdbc:sqlite:" + dbFile.getAbsolutePath();

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT * FROM authme")) {

            while (rs.next()) {
                try {
                    String username = rs.getString("username");
                    String hash = rs.getString("password");
                    String ip = rs.getString("ip");
                    String email = rs.getString("email");
                    long lastLogin = rs.getLong("lastlogin");
                    String realname = rs.getString("realname");

                    // Detect hash algorithm
                    HashAlgorithm algorithm = detectHashAlgorithm(hash);

                    Account account = new Account();
                    account.setUuid(UUID.nameUUIDFromBytes(
                            ("OfflinePlayer:" + realname).getBytes()));
                    account.setUsername(realname != null ? realname : username);
                    account.setNormalizedUsername(username.toLowerCase());
                    account.setPasswordHash(hash);
                    account.setHashAlgorithm(algorithm);
                    account.setStatus(AccountStatus.ACTIVE);
                    account.setEmail(email != null && !email.equals("your@email.com")
                            ? email : null);
                    account.setRole("guest");
                    account.setTwoFactorMethod(TwoFactorMethod.NONE);
                    account.setRegistrationIp(ip);
                    account.setLastLoginIp(ip);
                    account.setLastLoginDate(lastLogin > 0
                            ? Instant.ofEpochMilli(lastLogin) : null);
                    account.setCreatedAt(Instant.now());

                    storage.saveAccount(account).join();
                    count++;
                } catch (Exception e) {
                    logger.warning("[Migration] Error migrating user: " + e.getMessage());
                }
            }

        } catch (SQLException e) {
            logger.severe("[Migration] AuthMe migration failed: " + e.getMessage());
        }

        logger.info("[Migration] Migrated " + count + " accounts from AuthMe SQLite");
        core.getAuditService().logSystem(
                AuditEventType.MIGRATION,
                "Migrated " + count + " accounts from AuthMe SQLite"
        );
        return count;
    }

    /**
     * Migrate from AuthMe MySQL.
     */
    public int migrateFromAuthMeMySQL(String host, int port,
                                      String database, String username,
                                      String password, String tableName) {
        int count = 0;
        String url = String.format(
                "jdbc:mysql://%s:%d/%s?useSSL=false&allowPublicKeyRetrieval=true",
                host, port, database
        );

        try (Connection conn = DriverManager.getConnection(url, username, password);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM " + tableName)) {

            while (rs.next()) {
                try {
                    String name = rs.getString("username");
                    String hash = rs.getString("password");
                    String ip = rs.getString("ip");
                    String email = rs.getString("email");
                    String realname = rs.getString("realname");

                    HashAlgorithm algorithm = detectHashAlgorithm(hash);

                    Account account = new Account();
                    account.setUuid(UUID.nameUUIDFromBytes(
                            ("OfflinePlayer:" + (realname != null ? realname : name)).getBytes()));
                    account.setUsername(realname != null ? realname : name);
                    account.setNormalizedUsername(name.toLowerCase());
                    account.setPasswordHash(hash);
                    account.setHashAlgorithm(algorithm);
                    account.setStatus(AccountStatus.ACTIVE);
                    account.setEmail(email != null && !email.equals("your@email.com")
                            ? email : null);
                    account.setRole("guest");
                    account.setTwoFactorMethod(TwoFactorMethod.NONE);
                    account.setRegistrationIp(ip);
                    account.setLastLoginIp(ip);
                    account.setCreatedAt(Instant.now());

                    storage.saveAccount(account).join();
                    count++;
                } catch (Exception e) {
                    logger.warning("[Migration] Error: " + e.getMessage());
                }
            }

        } catch (SQLException e) {
            logger.severe("[Migration] AuthMe MySQL migration failed: " + e.getMessage());
        }

        logger.info("[Migration] Migrated " + count + " accounts from AuthMe MySQL");
        return count;
    }

    /**
     * Migrate from xAuth H2 database.
     */
    public int migrateFromXAuth(File dbFile) {
        if (!dbFile.exists()) {
            logger.warning("[Migration] xAuth DB not found: " + dbFile.getAbsolutePath());
            return 0;
        }

        int count = 0;
        String url = "jdbc:h2:" + dbFile.getAbsolutePath().replace(".mv.db", "");

        try {
            Class.forName("org.h2.Driver");
        } catch (ClassNotFoundException e) {
            logger.severe("[Migration] H2 driver not found. Add H2 to classpath.");
            return 0;
        }

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT * FROM accounts")) {

            while (rs.next()) {
                try {
                    String name = rs.getString("playername");
                    String hash = rs.getString("password");

                    Account account = new Account();
                    account.setUuid(UUID.nameUUIDFromBytes(
                            ("OfflinePlayer:" + name).getBytes()));
                    account.setUsername(name);
                    account.setNormalizedUsername(name.toLowerCase());
                    account.setPasswordHash(hash);
                    account.setHashAlgorithm(HashAlgorithm.XAUTH);
                    account.setStatus(AccountStatus.ACTIVE);
                    account.setRole("guest");
                    account.setTwoFactorMethod(TwoFactorMethod.NONE);
                    account.setCreatedAt(Instant.now());

                    storage.saveAccount(account).join();
                    count++;
                } catch (Exception e) {
                    logger.warning("[Migration] Error: " + e.getMessage());
                }
            }

        } catch (SQLException e) {
            logger.severe("[Migration] xAuth migration failed: " + e.getMessage());
        }

        logger.info("[Migration] Migrated " + count + " accounts from xAuth");
        return count;
    }

    /**
     * Migrate from CrazyLogin flat file.
     */
    public int migrateFromCrazyLogin(File dataFile) {
        if (!dataFile.exists()) {
            logger.warning("[Migration] CrazyLogin file not found");
            return 0;
        }

        int count = 0;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(dataFile)))) {

            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                // CrazyLogin format: name:hash:ip:...
                String[] parts = line.split(":");
                if (parts.length < 2) continue;

                try {
                    String name = parts[0];
                    String hash = parts[1];
                    String ip = parts.length > 2 ? parts[2] : null;

                    Account account = new Account();
                    account.setUuid(UUID.nameUUIDFromBytes(
                            ("OfflinePlayer:" + name).getBytes()));
                    account.setUsername(name);
                    account.setNormalizedUsername(name.toLowerCase());
                    account.setPasswordHash(hash);
                    account.setHashAlgorithm(detectHashAlgorithm(hash));
                    account.setStatus(AccountStatus.ACTIVE);
                    account.setRole("guest");
                    account.setTwoFactorMethod(TwoFactorMethod.NONE);
                    account.setRegistrationIp(ip);
                    account.setCreatedAt(Instant.now());

                    storage.saveAccount(account).join();
                    count++;
                } catch (Exception e) {
                    logger.warning("[Migration] Error on line: " + e.getMessage());
                }
            }

        } catch (IOException e) {
            logger.severe("[Migration] CrazyLogin migration failed: " + e.getMessage());
        }

        logger.info("[Migration] Migrated " + count + " accounts from CrazyLogin");
        return count;
    }

    /**
     * Detect hash algorithm from hash string format.
     */
    public static HashAlgorithm detectHashAlgorithm(String hash) {
        if (hash == null) return HashAlgorithm.SHA256;

        if (hash.startsWith("$argon2id$") || hash.startsWith("$argon2i$")) {
            return HashAlgorithm.ARGON2ID;
        }
        if (hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$")) {
            return HashAlgorithm.BCRYPT;
        }
        if (hash.startsWith("$pbkdf2$")) {
            return HashAlgorithm.PBKDF2;
        }
        if (hash.startsWith("$SHA$")) {
            return HashAlgorithm.SHA256;
        }
        if (hash.length() == 32 && hash.matches("[a-fA-F0-9]+")) {
            return HashAlgorithm.MD5;
        }
        if (hash.length() == 64 && hash.matches("[a-fA-F0-9]+")) {
            return HashAlgorithm.SHA256;
        }

        return HashAlgorithm.SHA256;
    }
}