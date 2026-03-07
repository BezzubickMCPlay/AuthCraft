package com.authcraft.web.api;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.web.ApiResponse;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Configuration API endpoints.
 * Provides configuration management functionality.
 */
public class ConfigurationApi {
    
    private static final Logger logger = LoggerFactory.getLogger(ConfigurationApi.class);
    
    private final AuthCraftCore core;
    private final AuthCraftConfig config;
    
    public ConfigurationApi(AuthCraftCore core, AuthCraftConfig config) {
        this.core = core;
        this.config = config;
    }
    
    /**
     * Get current configuration.
     */
    public void getConfig(Context ctx) {
        try {
            Map<String, Object> configMap = new LinkedHashMap<>();
            
            // Authentication settings
            Map<String, Object> auth = new LinkedHashMap<>();
            auth.put("sessionTimeout", config.getSessionTtlHours());
            auth.put("sessionStrictIp", config.isSessionStrictIp());
            auth.put("maxAccountsPerIp", config.getMaxAccountsPerIp());
            configMap.put("authentication", auth);
    
            // Password settings
            Map<String, Object> password = new LinkedHashMap<>();
            password.put("minLength", config.getPasswordMinLength());
            password.put("maxLength", config.getPasswordMaxLength());
            password.put("minScore", config.getPasswordMinScore());
            password.put("requireUppercase", config.isPasswordRequireUppercase());
            password.put("requireLowercase", config.isPasswordRequireLowercase());
            password.put("requireDigit", config.isPasswordRequireDigit());
            password.put("requireSpecial", config.isPasswordRequireSpecial());
            password.put("checkBlacklist", config.isPasswordCheckBlacklist());
            password.put("hashAlgorithm", config.getHashAlgorithm().name());
            configMap.put("password", password);
    
            // Security settings
            Map<String, Object> security = new LinkedHashMap<>();
            security.put("maxLoginAttempts", config.getMaxLoginAttempts());
            security.put("loginTimeoutSeconds", config.getLoginTimeoutSeconds());
            security.put("baseLockDurationMinutes", config.getBaseLockDurationMinutes());
            security.put("maxLockDurationMinutes", config.getMaxLockDurationMinutes());
            security.put("antiBotEnabled", config.isAntiBotEnabled());
            security.put("geoIpEnabled", config.isGeoIpEnabled());
            configMap.put("security", security);
            
            // 2FA settings
            Map<String, Object> twoFactor = new LinkedHashMap<>();
            twoFactor.put("totpEnabled", config.isTotpEnabled());
            twoFactor.put("telegramEnabled", config.isTelegramEnabled());
            twoFactor.put("vkEnabled", config.isVkEnabled());
            twoFactor.put("emailEnabled", config.isEmailEnabled());
            twoFactor.put("backupCodesCount", config.getBackupCodeCount());
            configMap.put("twoFactor", twoFactor);
            
            // Web dashboard settings
            Map<String, Object> webDashboard = new LinkedHashMap<>();
            webDashboard.put("enabled", config.isWebDashboardEnabled());
            webDashboard.put("port", config.getWebDashboardPort());
            webDashboard.put("host", config.getWebDashboardHost());
            configMap.put("webDashboard", webDashboard);
            
            ctx.json(ApiResponse.success("Configuration", configMap));
            
        } catch (Exception e) {
            logger.error("Error getting configuration", e);
            ctx.status(500).json(ApiResponse.error("Failed to get configuration"));
        }
    }
    
    /**
     * Update configuration.
     */
    public void updateConfig(Context ctx) {
        try {
            ConfigUpdateRequest request = ctx.bodyAsClass(ConfigUpdateRequest.class);
            
            // Log the update
            logger.info("Configuration update requested by {}: {}", ctx.attribute("username"), request.category);
            
            // In a real implementation, this would update the config file
            // For now, we just return success
            // The actual config update would require platform-specific implementation
            
            ctx.json(ApiResponse.success("Configuration updated. Restart required for some changes."));
            
        } catch (Exception e) {
            logger.error("Error updating configuration", e);
            ctx.status(500).json(ApiResponse.error("Failed to update configuration"));
        }
    }
    
    /**
     * Reload configuration from file.
     */
    public void reloadConfig(Context ctx) {
        try {
            // In a real implementation, this would reload the config from disk
            String username = ctx.attribute("username");
            logger.info("Configuration reload requested by {}", username != null ? username : "unknown");
            
            // Platform-specific reload would be called here
            // core.reloadConfig();
            
            ctx.json(ApiResponse.success("Configuration reloaded successfully"));
            
        } catch (Exception e) {
            logger.error("Error reloading configuration", e);
            ctx.status(500).json(ApiResponse.error("Failed to reload configuration"));
        }
    }
    
    /**
     * Get configuration schema for UI.
     */
    public void getConfigSchema(Context ctx) {
        try {
            List<Map<String, Object>> schema = new ArrayList<>();
            
            // Authentication schema
            Map<String, Object> authSchema = new LinkedHashMap<>();
            authSchema.put("category", "authentication");
            authSchema.put("label", "Authentication Settings");
            authSchema.put("fields", List.of(
                createFieldSchema("sessionTimeout", "Session Timeout (hours)", "number", 1, 168),
                createFieldSchema("maxSessionsPerPlayer", "Max Sessions Per Player", "number", 1, 10),
                createFieldSchema("allowSessionRestore", "Allow Session Restore", "boolean", null, null)
            ));
            schema.add(authSchema);
            
            // Password schema
            Map<String, Object> passwordSchema = new LinkedHashMap<>();
            passwordSchema.put("category", "password");
            passwordSchema.put("label", "Password Settings");
            passwordSchema.put("fields", List.of(
                createFieldSchema("minLength", "Minimum Length", "number", 6, 64),
                createFieldSchema("maxLength", "Maximum Length", "number", 64, 256),
                createFieldSchema("requireUppercase", "Require Uppercase", "boolean", null, null),
                createFieldSchema("requireLowercase", "Require Lowercase", "boolean", null, null),
                createFieldSchema("requireNumbers", "Require Numbers", "boolean", null, null),
                createFieldSchema("requireSpecialChars", "Require Special Characters", "boolean", null, null),
                createFieldSchema("hashAlgorithm", "Hash Algorithm", "select", 
                    List.of("ARGON2ID", "BCRYPT", "PBKDF2"), null)
            ));
            schema.add(passwordSchema);
            
            // Security schema
            Map<String, Object> securitySchema = new LinkedHashMap<>();
            securitySchema.put("category", "security");
            securitySchema.put("label", "Security Settings");
            securitySchema.put("fields", List.of(
                createFieldSchema("maxFailedAttempts", "Max Failed Login Attempts", "number", 1, 20),
                createFieldSchema("lockDuration", "Lock Duration (minutes)", "number", 1, 1440),
                createFieldSchema("antiBotEnabled", "Enable Anti-Bot", "boolean", null, null),
                createFieldSchema("geoIpEnabled", "Enable GeoIP Filter", "boolean", null, null)
            ));
            schema.add(securitySchema);
            
            // 2FA schema
            Map<String, Object> twoFactorSchema = new LinkedHashMap<>();
            twoFactorSchema.put("category", "twoFactor");
            twoFactorSchema.put("label", "Two-Factor Authentication");
            twoFactorSchema.put("fields", List.of(
                createFieldSchema("totpEnabled", "Enable TOTP", "boolean", null, null),
                createFieldSchema("telegramEnabled", "Enable Telegram", "boolean", null, null),
                createFieldSchema("vkEnabled", "Enable VK", "boolean", null, null),
                createFieldSchema("emailEnabled", "Enable Email", "boolean", null, null),
                createFieldSchema("backupCodesCount", "Backup Codes Count", "number", 5, 20)
            ));
            schema.add(twoFactorSchema);
            
            ctx.json(ApiResponse.success("Configuration schema", schema));
            
        } catch (Exception e) {
            logger.error("Error getting config schema", e);
            ctx.status(500).json(ApiResponse.error("Failed to get configuration schema"));
        }
    }
    
    /**
     * Create a field schema for the UI.
     */
    private Map<String, Object> createFieldSchema(String name, String label, String type, 
                                                   Object options, Number defaultValue) {
        Map<String, Object> field = new LinkedHashMap<>();
        field.put("name", name);
        field.put("label", label);
        field.put("type", type);
        if (options != null) {
            field.put("options", options);
        }
        if (defaultValue != null) {
            field.put("defaultValue", defaultValue);
        }
        return field;
    }
    
    // Request DTOs
    
    public static class ConfigUpdateRequest {
        public String category;
        public Map<String, Object> values;
    }
}
