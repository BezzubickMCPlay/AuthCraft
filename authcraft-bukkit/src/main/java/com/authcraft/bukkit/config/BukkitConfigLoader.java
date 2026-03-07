// com/authcraft/bukkit/config/BukkitConfigLoader.java
package com.authcraft.bukkit.config;

import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.HashAlgorithm;
import org.bukkit.configuration.file.FileConfiguration;

import java.util.List;

public class BukkitConfigLoader {

    public static AuthCraftConfig load(FileConfiguration yml) {
        AuthCraftConfig config = new AuthCraftConfig();

        // Database
        config.setDatabaseType(
                yml.getString("database.type", "sqlite"));
        config.setDatabaseHost(
                yml.getString("database.host", "localhost"));
        config.setDatabasePort(
                yml.getInt("database.port", 3306));
        config.setDatabaseName(
                yml.getString("database.name", "authcraft"));
        config.setDatabaseUsername(
                yml.getString("database.username", "root"));
        config.setDatabasePassword(
                yml.getString("database.password", ""));
        config.setDatabaseFile(
                yml.getString("database.file", "authcraft.db"));
        config.setHikariMaxPoolSize(
                yml.getInt("database.pool-size", 10));

        // Hashing
        config.setHashAlgorithm(HashAlgorithm.fromId(
                yml.getString("security.hash-algorithm", "argon2id")));
        config.setArgon2Iterations(
                yml.getInt("security.argon2.iterations", 3));
        config.setArgon2Memory(
                yml.getInt("security.argon2.memory", 65536));
        config.setArgon2Parallelism(
                yml.getInt("security.argon2.parallelism", 1));
        config.setBcryptCost(
                yml.getInt("security.bcrypt.cost", 12));

        // Password policy
        config.setPasswordMinLength(
                yml.getInt("password-policy.min-length", 8));
        config.setPasswordMaxLength(
                yml.getInt("password-policy.max-length", 128));
        config.setPasswordMinScore(
                yml.getInt("password-policy.min-score", 50));
        config.setPasswordRequireUppercase(
                yml.getBoolean("password-policy.require-uppercase", true));
        config.setPasswordRequireLowercase(
                yml.getBoolean("password-policy.require-lowercase", true));
        config.setPasswordRequireDigit(
                yml.getBoolean("password-policy.require-digit", true));
        config.setPasswordRequireSpecial(
                yml.getBoolean("password-policy.require-special", false));
        config.setPasswordCheckBlacklist(
                yml.getBoolean("password-policy.check-blacklist", true));

        // Session
        config.setSessionTtlHours(
                yml.getLong("session.ttl-hours", 168));
        config.setSessionStrictIp(
                yml.getBoolean("session.strict-ip", true));

        // Login
        config.setMaxLoginAttempts(
                yml.getInt("login.max-attempts", 5));
        config.setBaseLockDurationMinutes(
                yml.getLong("login.base-lock-minutes", 5));
        config.setMaxLockDurationMinutes(
                yml.getLong("login.max-lock-minutes", 1440));
        config.setMaxAccountsPerIp(
                yml.getInt("login.max-accounts-per-ip", 3));

        // 2FA
        config.setTotpEnabled(
                yml.getBoolean("2fa.totp.enabled", true));
        config.setTelegramEnabled(
                yml.getBoolean("2fa.telegram.enabled", false));
        config.setTelegramBotToken(
                yml.getString("2fa.telegram.bot-token", ""));
        config.setVkEnabled(
                yml.getBoolean("2fa.vk.enabled", false));
        config.setVkBotToken(
                yml.getString("2fa.vk.bot-token", ""));
        config.setEmailEnabled(
                yml.getBoolean("2fa.email.enabled", false));
        config.setSmtpHost(
                yml.getString("2fa.email.smtp-host", ""));
        config.setSmtpPort(
                yml.getInt("2fa.email.smtp-port", 587));
        config.setBackupCodeCount(
                yml.getInt("2fa.backup-code-count", 10));

        // AntiBot
        config.setAntiBotEnabled(
                yml.getBoolean("antibot.enabled", true));
        config.setAntiBotMaxConnectionsPerIp(
                yml.getInt("antibot.max-connections-per-ip", 5));
        config.setAntiBotWindowSeconds(
                yml.getInt("antibot.window-seconds", 60));
        config.setAntiBotGlobalMaxPerSecond(
                yml.getInt("antibot.global-max-per-second", 100));
        config.setAntiBotConfidenceThreshold(
                yml.getDouble("antibot.confidence-threshold", 0.7));
        config.setAntiBotPatternAnalysis(
                yml.getBoolean("antibot.pattern-analysis", true));

        // GeoIP
        config.setGeoIpEnabled(
                yml.getBoolean("geoip.enabled", false));
        config.setGeoIpMode(
                yml.getString("geoip.mode", "blacklist"));
        config.setGeoIpCountries(
                yml.getStringList("geoip.countries"));

        // Unicode
        config.setUnicodeSpoofingDetection(
                yml.getBoolean("unicode-spoofing.enabled", true));
        config.setUnicodeSimilarityThreshold(
                yml.getDouble("unicode-spoofing.threshold", 0.8));

        // Security Audit
        config.setSecurityAuditOnStartup(
                yml.getBoolean("security-audit.enabled", true));
        config.setSecurityAuditCheckPorts(
                yml.getBoolean("security-audit.check-ports", true));
        config.setSecurityAuditCheckRcon(
                yml.getBoolean("security-audit.check-rcon", true));

        // Notifications
        config.setNotifyAdminOnFailedLogin(
                yml.getBoolean("notifications.admin-on-failed-login",
                        true));
        config.setNotifyAdminAfterAttempts(
                yml.getInt("notifications.after-attempts", 2));

        // Language
        config.setDefaultLanguage(
                yml.getString("language", "ru"));

        // Limbo
        config.setLimboReminderIntervalSeconds(
            yml.getInt("limbo.reminder-interval", 10));

        // Debug
        config.setDebugMode(
            yml.getBoolean("debug.enabled", false));
        config.setDebugIntegrations(
            yml.getBoolean("debug.integrations", false));
        config.setDebugStorage(
            yml.getBoolean("debug.storage", false));
        config.setDebugAuth(
            yml.getBoolean("debug.auth", false));

        return config;
    }
}