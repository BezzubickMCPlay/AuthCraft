// com/authcraft/core/config/AuthCraftConfig.java
package com.authcraft.core.config;

import com.authcraft.core.model.HashAlgorithm;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class AuthCraftConfig {

    // === Database ===
    private String databaseType = "sqlite"; // mysql, postgresql, sqlite
    private String databaseHost = "localhost";
    private int databasePort = 3306;
    private String databaseName = "authcraft";
    private String databaseUsername = "root";
    private String databasePassword = "";
    private String databaseFile = "authcraft.db";
    private int hikariMaxPoolSize = 10;
    private long hikariConnectionTimeout = 30000;

    // === Hashing ===
    private HashAlgorithm hashAlgorithm = HashAlgorithm.ARGON2ID;
    private int argon2Iterations = 3;
    private int argon2Memory = 65536; // KB
    private int argon2Parallelism = 1;
    private int bcryptCost = 12;
    private int pbkdf2Iterations = 100000;

    // === Password Policy ===
    private int passwordMinLength = 8;
    private int passwordMaxLength = 128;
    private int passwordMinScore = 50;
    private boolean passwordRequireUppercase = true;
    private boolean passwordRequireLowercase = true;
    private boolean passwordRequireDigit = true;
    private boolean passwordRequireSpecial = false;
    private boolean passwordCheckBlacklist = true;
    private boolean passwordCheckSequences = true;
    private boolean passwordCheckUsername = true;

    // === Session ===
    private long sessionTtlHours = 168; // 7 days
    private boolean sessionStrictIp = true;
    private int sessionCleanupIntervalMinutes = 30;

    // === Login Security ===
    private int maxLoginAttempts = 5;
    private int loginTimeoutSeconds = 60;
    private long baseLockDurationMinutes = 5;
    private long maxLockDurationMinutes = 1440; // 24h
    private double lockExponentialBase = 5.0;
    private int maxAccountsPerIp = 3;

    // === 2FA ===
    private boolean totpEnabled = true;
    private boolean telegramEnabled = false;
    private String telegramBotToken = "";
    private boolean vkEnabled = false;
    private String vkBotToken = "";
    private boolean emailEnabled = false;
    private String smtpHost = "";
    private int smtpPort = 587;
    private String smtpUsername = "";
    private String smtpPassword = "";
    private boolean smtpTls = true;
    private String emailFrom = "authcraft@server.com";
    private int backupCodeCount = 10;
    private int twoFactorMaxAttempts = 3;

    // === AntiBot ===
    private boolean antiBotEnabled = true;
    private int antiBotMaxConnectionsPerIp = 5;
    private int antiBotWindowSeconds = 60;
    private int antiBotGlobalMaxPerSecond = 100;
    private double antiBotConfidenceThreshold = 0.7;
    private boolean antiBotPatternAnalysis = true;

    // === ML Bot Detection ===
    private boolean mlBotDetectionEnabled = true;
    private double mlBehaviorWeight = 0.25;
    private double mlAnomalyWeight = 0.20;
    private double mlUsernameWeight = 0.20;
    private double mlThreatIntelWeight = 0.25;
    private double mlRateLimitWeight = 0.10;
    private double mlBlockThreshold = 0.7;
    private double mlChallengeThreshold = 0.4;
    private boolean mlAdaptiveRateLimit = true;
    private int mlBaseRateLimit = 10;
    private boolean mlThreatIntelEnabled = true;
    private boolean mlBehaviorTracking = true;
    private int mlProfileRetentionHours = 24;

    // === GeoIP ===
    private boolean geoIpEnabled = false;
    private String geoIpMode = "blacklist"; // whitelist or blacklist
    private List<String> geoIpCountries = Arrays.asList("CN", "KP");
    private String geoIpDatabasePath = "GeoLite2-Country.mmdb";

    // === Threat Protection ===
    private boolean threatProtectionEnabled = true;
    private boolean blockTorExitNodes = true;
    private boolean blockVPNProxies = false;
    private boolean checkIPReputation = true;
    private boolean detectDistributedAttacks = true;
    private double threatBlockThreshold = 0.7;
    private double threatChallengeThreshold = 0.4;
    private int reputationCacheTTLMinutes = 30;
    private boolean loadMaliciousIPList = true;
    private String maliciousIPListUrl = "";
    private boolean autoUpdateThreatFeeds = true;
    private int threatFeedUpdateIntervalHours = 24;

    // === Unicode Spoofing ===
    private boolean unicodeSpoofingDetection = true;
    private double unicodeSimilarityThreshold = 0.8;

    // === Security Audit ===
    private boolean securityAuditOnStartup = true;
    private boolean securityAuditCheckPorts = true;
    private boolean securityAuditCheckRcon = true;
    private boolean securityAuditCheckPlugins = true;
    private boolean securityAuditCheckPermissions = true;

    // === Logging ===
    private boolean auditLogEnabled = true;
    private boolean auditLogToFile = true;
    private boolean auditLogToDatabase = true;
    private String auditLogFile = "audit.log";

    // === Notifications ===
    private boolean notifyAdminOnFailedLogin = true;
    private int notifyAdminAfterAttempts = 2;
    private boolean notifyNewIpLogin = false;
    private boolean telegramNotifications = false;
    private String telegramAdminChatId = "";

    // === Localization ===
    private String defaultLanguage = "ru";
    private List<String> supportedLanguages = Arrays.asList(
        "ru", "en", "de", "fr", "es", "pt", "pl",
        "zh_cn", "zh_tw", "ja", "ko"
    );

    // === Backup ===
    private boolean autoBackupEnabled = true;
    private int autoBackupIntervalHours = 24;
    private int autoBackupRetentionDays = 7;
    private boolean autoBackupCompress = true;

    // === Limbo ===
    private boolean limboBlindness = true;
    private boolean limboInvisibility = true;
    private boolean limboFreezeMovement = true;
    private int limboReminderIntervalSeconds = 10;

    // === Debug Mode ===
    private boolean debugMode = false;
    private boolean debugIntegrations = false; // VK, Telegram, Email
    private boolean debugStorage = false;
    private boolean debugAuth = false;

    // === Web Dashboard ===
    private boolean webDashboardEnabled = false;
    private int webDashboardPort = 8080;
    private String webDashboardHost = "0.0.0.0";
    private String webDashboardSecret = "change-this-secret-key";
    private boolean webDashboardHttps = false;
    private String webDashboardSslCert = "";
    private String webDashboardSslKey = "";

    // === Trusted Device (Remember this device) ===
    private boolean trustedDeviceEnabled = true;
    private int trustedDeviceTtlDays = 30;
    private int maxTrustedDevicesPerPlayer = 5;

    // === Login Notifications ===
    private boolean loginNotificationsEnabled = true;
    private boolean loginNotifyOnNewIp = true;
    private boolean loginNotifyOnNewDevice = true;
    private boolean loginNotifyOnSessionRestored = false;

    // === Redis Multi-Server Sync ===
    private boolean redisSyncEnabled = false;
    private String redisHost = "localhost";
    private int redisPort = 6379;
    private String redisPassword = "";
    private int redisDatabase = 0;
    private int redisMaxConnections = 10;
    private int redisMaxIdle = 5;
    private int redisMinIdle = 1;
    private int redisTimeoutMs = 5000;
    private boolean redisSSLEnabled = false;
    private String serverName = "";

    // === GDPR Compliance ===
    private int deletionGracePeriodDays = 7;
    private boolean gdprDataExportEnabled = true;
    private boolean gdprRightToBeForgottenEnabled = true;
    private int dataRetentionDays = 90;

    // === Social Authentication (OAuth2) ===
    private boolean discordAuthEnabled = false;
    private String discordClientId = "";
    private String discordClientSecret = "";
    private String discordRedirectUri = "";

    private boolean googleAuthEnabled = false;
    private String googleClientId = "";
    private String googleClientSecret = "";
    private String googleRedirectUri = "";

    private boolean microsoftAuthEnabled = false;
    private String microsoftClientId = "";
    private String microsoftClientSecret = "";
    private String microsoftRedirectUri = "";

    private boolean accountMergeEnabled = true;
    private int oauthStateExpirationMinutes = 10;

    // All getters and setters below

    public String getDatabaseType() { return databaseType; }
    public void setDatabaseType(String t) { this.databaseType = t; }

    public String getDatabaseHost() { return databaseHost; }
    public void setDatabaseHost(String h) { this.databaseHost = h; }

    public int getDatabasePort() { return databasePort; }
    public void setDatabasePort(int p) { this.databasePort = p; }

    public String getDatabaseName() { return databaseName; }
    public void setDatabaseName(String n) { this.databaseName = n; }

    public String getDatabaseUsername() { return databaseUsername; }
    public void setDatabaseUsername(String u) { this.databaseUsername = u; }

    public String getDatabasePassword() { return databasePassword; }
    public void setDatabasePassword(String p) { this.databasePassword = p; }

    public String getDatabaseFile() { return databaseFile; }
    public void setDatabaseFile(String f) { this.databaseFile = f; }

    public int getHikariMaxPoolSize() { return hikariMaxPoolSize; }
    public void setHikariMaxPoolSize(int s) { this.hikariMaxPoolSize = s; }

    public long getHikariConnectionTimeout() { return hikariConnectionTimeout; }
    public void setHikariConnectionTimeout(long t) { this.hikariConnectionTimeout = t; }

    public HashAlgorithm getHashAlgorithm() { return hashAlgorithm; }
    public void setHashAlgorithm(HashAlgorithm a) { this.hashAlgorithm = a; }

    public int getArgon2Iterations() { return argon2Iterations; }
    public void setArgon2Iterations(int i) { this.argon2Iterations = i; }

    public int getArgon2Memory() { return argon2Memory; }
    public void setArgon2Memory(int m) { this.argon2Memory = m; }

    public int getArgon2Parallelism() { return argon2Parallelism; }
    public void setArgon2Parallelism(int p) { this.argon2Parallelism = p; }

    public int getBcryptCost() { return bcryptCost; }
    public void setBcryptCost(int c) { this.bcryptCost = c; }

    public int getPbkdf2Iterations() { return pbkdf2Iterations; }
    public void setPbkdf2Iterations(int i) { this.pbkdf2Iterations = i; }

    public int getPasswordMinLength() { return passwordMinLength; }
    public void setPasswordMinLength(int l) { this.passwordMinLength = l; }

    public int getPasswordMaxLength() { return passwordMaxLength; }
    public void setPasswordMaxLength(int l) { this.passwordMaxLength = l; }

    public int getPasswordMinScore() { return passwordMinScore; }
    public void setPasswordMinScore(int s) { this.passwordMinScore = s; }

    public boolean isPasswordRequireUppercase() { return passwordRequireUppercase; }
    public void setPasswordRequireUppercase(boolean b) { this.passwordRequireUppercase = b; }

    public boolean isPasswordRequireLowercase() { return passwordRequireLowercase; }
    public void setPasswordRequireLowercase(boolean b) { this.passwordRequireLowercase = b; }

    public boolean isPasswordRequireDigit() { return passwordRequireDigit; }
    public void setPasswordRequireDigit(boolean b) { this.passwordRequireDigit = b; }

    public boolean isPasswordRequireSpecial() { return passwordRequireSpecial; }
    public void setPasswordRequireSpecial(boolean b) { this.passwordRequireSpecial = b; }

    public boolean isPasswordCheckBlacklist() { return passwordCheckBlacklist; }
    public void setPasswordCheckBlacklist(boolean b) { this.passwordCheckBlacklist = b; }

    public boolean isPasswordCheckSequences() { return passwordCheckSequences; }
    public void setPasswordCheckSequences(boolean b) { this.passwordCheckSequences = b; }

    public boolean isPasswordCheckUsername() { return passwordCheckUsername; }
    public void setPasswordCheckUsername(boolean b) { this.passwordCheckUsername = b; }

    public long getSessionTtlHours() { return sessionTtlHours; }
    public void setSessionTtlHours(long h) { this.sessionTtlHours = h; }

    public boolean isSessionStrictIp() { return sessionStrictIp; }
    public void setSessionStrictIp(boolean b) { this.sessionStrictIp = b; }

    public int getSessionCleanupIntervalMinutes() {
        return sessionCleanupIntervalMinutes;
    }
    public void setSessionCleanupIntervalMinutes(int m) {
        this.sessionCleanupIntervalMinutes = m;
    }

    public int getMaxLoginAttempts() { return maxLoginAttempts; }
    public void setMaxLoginAttempts(int a) { this.maxLoginAttempts = a; }

    public int getLoginTimeoutSeconds() { return loginTimeoutSeconds; }
    public void setLoginTimeoutSeconds(int s) { this.loginTimeoutSeconds = s; }

    public long getBaseLockDurationMinutes() { return baseLockDurationMinutes; }
    public void setBaseLockDurationMinutes(long m) {
        this.baseLockDurationMinutes = m;
    }

    public long getMaxLockDurationMinutes() { return maxLockDurationMinutes; }
    public void setMaxLockDurationMinutes(long m) { this.maxLockDurationMinutes = m; }

    public double getLockExponentialBase() { return lockExponentialBase; }
    public void setLockExponentialBase(double b) { this.lockExponentialBase = b; }

    public int getMaxAccountsPerIp() { return maxAccountsPerIp; }
    public void setMaxAccountsPerIp(int m) { this.maxAccountsPerIp = m; }

    public boolean isTotpEnabled() { return totpEnabled; }
    public void setTotpEnabled(boolean b) { this.totpEnabled = b; }

    public boolean isTelegramEnabled() { return telegramEnabled; }
    public void setTelegramEnabled(boolean b) { this.telegramEnabled = b; }

    public String getTelegramBotToken() { return telegramBotToken; }
    public void setTelegramBotToken(String t) { this.telegramBotToken = t; }

    public boolean isVkEnabled() { return vkEnabled; }
    public void setVkEnabled(boolean b) { this.vkEnabled = b; }

    public String getVkBotToken() { return vkBotToken; }
    public void setVkBotToken(String t) { this.vkBotToken = t; }

    public boolean isEmailEnabled() { return emailEnabled; }
    public void setEmailEnabled(boolean b) { this.emailEnabled = b; }

    public String getSmtpHost() { return smtpHost; }
    public void setSmtpHost(String h) { this.smtpHost = h; }

    public int getSmtpPort() { return smtpPort; }
    public void setSmtpPort(int p) { this.smtpPort = p; }

    public String getSmtpUsername() { return smtpUsername; }
    public void setSmtpUsername(String u) { this.smtpUsername = u; }

    public String getSmtpPassword() { return smtpPassword; }
    public void setSmtpPassword(String p) { this.smtpPassword = p; }

    public boolean isSmtpTls() { return smtpTls; }
    public void setSmtpTls(boolean b) { this.smtpTls = b; }

    public String getEmailFrom() { return emailFrom; }
    public void setEmailFrom(String f) { this.emailFrom = f; }

    public int getBackupCodeCount() { return backupCodeCount; }
    public void setBackupCodeCount(int c) { this.backupCodeCount = c; }

    public int getTwoFactorMaxAttempts() { return twoFactorMaxAttempts; }
    public void setTwoFactorMaxAttempts(int a) { this.twoFactorMaxAttempts = a; }

    public boolean isAntiBotEnabled() { return antiBotEnabled; }
    public void setAntiBotEnabled(boolean b) { this.antiBotEnabled = b; }

    public int getAntiBotMaxConnectionsPerIp() {
        return antiBotMaxConnectionsPerIp;
    }
    public void setAntiBotMaxConnectionsPerIp(int m) {
        this.antiBotMaxConnectionsPerIp = m;
    }

    public int getAntiBotWindowSeconds() { return antiBotWindowSeconds; }
    public void setAntiBotWindowSeconds(int s) { this.antiBotWindowSeconds = s; }

    public int getAntiBotGlobalMaxPerSecond() {
        return antiBotGlobalMaxPerSecond;
    }
    public void setAntiBotGlobalMaxPerSecond(int m) {
        this.antiBotGlobalMaxPerSecond = m;
    }

    public double getAntiBotConfidenceThreshold() {
        return antiBotConfidenceThreshold;
    }
    public void setAntiBotConfidenceThreshold(double t) {
        this.antiBotConfidenceThreshold = t;
    }

    public boolean isAntiBotPatternAnalysis() { return antiBotPatternAnalysis; }
    public void setAntiBotPatternAnalysis(boolean b) {
        this.antiBotPatternAnalysis = b;
    }

    // === ML Bot Detection Getters/Setters ===
    public boolean isMlBotDetectionEnabled() { return mlBotDetectionEnabled; }
    public void setMlBotDetectionEnabled(boolean b) { this.mlBotDetectionEnabled = b; }

    public double getMlBehaviorWeight() { return mlBehaviorWeight; }
    public void setMlBehaviorWeight(double w) { this.mlBehaviorWeight = w; }

    public double getMlAnomalyWeight() { return mlAnomalyWeight; }
    public void setMlAnomalyWeight(double w) { this.mlAnomalyWeight = w; }

    public double getMlUsernameWeight() { return mlUsernameWeight; }
    public void setMlUsernameWeight(double w) { this.mlUsernameWeight = w; }

    public double getMlThreatIntelWeight() { return mlThreatIntelWeight; }
    public void setMlThreatIntelWeight(double w) { this.mlThreatIntelWeight = w; }

    public double getMlRateLimitWeight() { return mlRateLimitWeight; }
    public void setMlRateLimitWeight(double w) { this.mlRateLimitWeight = w; }

    public double getMlBlockThreshold() { return mlBlockThreshold; }
    public void setMlBlockThreshold(double t) { this.mlBlockThreshold = t; }

    public double getMlChallengeThreshold() { return mlChallengeThreshold; }
    public void setMlChallengeThreshold(double t) { this.mlChallengeThreshold = t; }

    public boolean isMlAdaptiveRateLimit() { return mlAdaptiveRateLimit; }
    public void setMlAdaptiveRateLimit(boolean b) { this.mlAdaptiveRateLimit = b; }

    public int getMlBaseRateLimit() { return mlBaseRateLimit; }
    public void setMlBaseRateLimit(int l) { this.mlBaseRateLimit = l; }

    public boolean isMlThreatIntelEnabled() { return mlThreatIntelEnabled; }
    public void setMlThreatIntelEnabled(boolean b) { this.mlThreatIntelEnabled = b; }

    public boolean isMlBehaviorTracking() { return mlBehaviorTracking; }
    public void setMlBehaviorTracking(boolean b) { this.mlBehaviorTracking = b; }

    public int getMlProfileRetentionHours() { return mlProfileRetentionHours; }
    public void setMlProfileRetentionHours(int h) { this.mlProfileRetentionHours = h; }

    public boolean isGeoIpEnabled() { return geoIpEnabled; }
    public void setGeoIpEnabled(boolean b) { this.geoIpEnabled = b; }

    public String getGeoIpMode() { return geoIpMode; }
    public void setGeoIpMode(String m) { this.geoIpMode = m; }

    public List<String> getGeoIpCountries() { return geoIpCountries; }
    public void setGeoIpCountries(List<String> c) { this.geoIpCountries = c; }

    public String getGeoIpDatabasePath() { return geoIpDatabasePath; }
    public void setGeoIpDatabasePath(String p) { this.geoIpDatabasePath = p; }

    // === Threat Protection Getters/Setters ===
    public boolean isThreatProtectionEnabled() { return threatProtectionEnabled; }
    public void setThreatProtectionEnabled(boolean b) { this.threatProtectionEnabled = b; }

    public boolean isBlockTorExitNodes() { return blockTorExitNodes; }
    public void setBlockTorExitNodes(boolean b) { this.blockTorExitNodes = b; }

    public boolean isBlockVPNProxies() { return blockVPNProxies; }
    public void setBlockVPNProxies(boolean b) { this.blockVPNProxies = b; }

    public boolean isCheckIPReputation() { return checkIPReputation; }
    public void setCheckIPReputation(boolean b) { this.checkIPReputation = b; }

    public boolean isDetectDistributedAttacks() { return detectDistributedAttacks; }
    public void setDetectDistributedAttacks(boolean b) { this.detectDistributedAttacks = b; }

    public double getThreatBlockThreshold() { return threatBlockThreshold; }
    public void setThreatBlockThreshold(double t) { this.threatBlockThreshold = t; }

    public double getThreatChallengeThreshold() { return threatChallengeThreshold; }
    public void setThreatChallengeThreshold(double t) { this.threatChallengeThreshold = t; }

    public int getReputationCacheTTLMinutes() { return reputationCacheTTLMinutes; }
    public void setReputationCacheTTLMinutes(int m) { this.reputationCacheTTLMinutes = m; }

    public boolean isLoadMaliciousIPList() { return loadMaliciousIPList; }
    public void setLoadMaliciousIPList(boolean b) { this.loadMaliciousIPList = b; }

    public String getMaliciousIPListUrl() { return maliciousIPListUrl; }
    public void setMaliciousIPListUrl(String u) { this.maliciousIPListUrl = u; }

    public boolean isAutoUpdateThreatFeeds() { return autoUpdateThreatFeeds; }
    public void setAutoUpdateThreatFeeds(boolean b) { this.autoUpdateThreatFeeds = b; }

    public int getThreatFeedUpdateIntervalHours() { return threatFeedUpdateIntervalHours; }
    public void setThreatFeedUpdateIntervalHours(int h) { this.threatFeedUpdateIntervalHours = h; }

    public boolean isUnicodeSpoofingDetection() {
        return unicodeSpoofingDetection;
    }
    public void setUnicodeSpoofingDetection(boolean b) {
        this.unicodeSpoofingDetection = b;
    }

    public double getUnicodeSimilarityThreshold() {
        return unicodeSimilarityThreshold;
    }
    public void setUnicodeSimilarityThreshold(double t) {
        this.unicodeSimilarityThreshold = t;
    }

    public boolean isSecurityAuditOnStartup() { return securityAuditOnStartup; }
    public void setSecurityAuditOnStartup(boolean b) {
        this.securityAuditOnStartup = b;
    }

    public boolean isSecurityAuditCheckPorts() {
        return securityAuditCheckPorts;
    }
    public void setSecurityAuditCheckPorts(boolean b) {
        this.securityAuditCheckPorts = b;
    }

    public boolean isSecurityAuditCheckRcon() { return securityAuditCheckRcon; }
    public void setSecurityAuditCheckRcon(boolean b) {
        this.securityAuditCheckRcon = b;
    }

    public boolean isSecurityAuditCheckPlugins() {
        return securityAuditCheckPlugins;
    }
    public void setSecurityAuditCheckPlugins(boolean b) {
        this.securityAuditCheckPlugins = b;
    }

    public boolean isSecurityAuditCheckPermissions() {
        return securityAuditCheckPermissions;
    }
    public void setSecurityAuditCheckPermissions(boolean b) {
        this.securityAuditCheckPermissions = b;
    }

    public boolean isAuditLogEnabled() { return auditLogEnabled; }
    public void setAuditLogEnabled(boolean b) { this.auditLogEnabled = b; }

    public boolean isAuditLogToFile() { return auditLogToFile; }
    public void setAuditLogToFile(boolean b) { this.auditLogToFile = b; }

    public boolean isAuditLogToDatabase() { return auditLogToDatabase; }
    public void setAuditLogToDatabase(boolean b) { this.auditLogToDatabase = b; }

    public String getAuditLogFile() { return auditLogFile; }
    public void setAuditLogFile(String f) { this.auditLogFile = f; }

    public boolean isNotifyAdminOnFailedLogin() {
        return notifyAdminOnFailedLogin;
    }
    public void setNotifyAdminOnFailedLogin(boolean b) {
        this.notifyAdminOnFailedLogin = b;
    }

    public int getNotifyAdminAfterAttempts() { return notifyAdminAfterAttempts; }
    public void setNotifyAdminAfterAttempts(int a) {
        this.notifyAdminAfterAttempts = a;
    }

    public boolean isNotifyNewIpLogin() { return notifyNewIpLogin; }
    public void setNotifyNewIpLogin(boolean b) { this.notifyNewIpLogin = b; }

    public boolean isTelegramNotifications() { return telegramNotifications; }
    public void setTelegramNotifications(boolean b) {
        this.telegramNotifications = b;
    }

    public String getTelegramAdminChatId() { return telegramAdminChatId; }
    public void setTelegramAdminChatId(String id) {
        this.telegramAdminChatId = id;
    }

    public String getDefaultLanguage() { return defaultLanguage; }
    public void setDefaultLanguage(String l) { this.defaultLanguage = l; }

    public List<String> getSupportedLanguages() { return supportedLanguages; }
    public void setSupportedLanguages(List<String> l) {
        this.supportedLanguages = l;
    }

    public boolean isAutoBackupEnabled() { return autoBackupEnabled; }
    public void setAutoBackupEnabled(boolean b) { this.autoBackupEnabled = b; }

    public int getAutoBackupIntervalHours() { return autoBackupIntervalHours; }
    public void setAutoBackupIntervalHours(int h) {
        this.autoBackupIntervalHours = h;
    }

    public int getAutoBackupRetentionDays() { return autoBackupRetentionDays; }
    public void setAutoBackupRetentionDays(int d) {
        this.autoBackupRetentionDays = d;
    }

    public boolean isAutoBackupCompress() { return autoBackupCompress; }
    public void setAutoBackupCompress(boolean b) { this.autoBackupCompress = b; }

    public boolean isLimboBlindness() { return limboBlindness; }
    public void setLimboBlindness(boolean b) { this.limboBlindness = b; }

    public boolean isLimboInvisibility() { return limboInvisibility; }
    public void setLimboInvisibility(boolean b) { this.limboInvisibility = b; }

    public boolean isLimboFreezeMovement() { return limboFreezeMovement; }
    public void setLimboFreezeMovement(boolean b) { this.limboFreezeMovement = b; }

    public int getLimboReminderIntervalSeconds() {
        return limboReminderIntervalSeconds;
    }
    public void setLimboReminderIntervalSeconds(int s) {
        this.limboReminderIntervalSeconds = s;
    }

    // === Debug Mode ===
    public boolean isDebugMode() { return debugMode; }
    public void setDebugMode(boolean b) { this.debugMode = b; }

    public boolean isDebugIntegrations() { return debugIntegrations || debugMode; }
    public void setDebugIntegrations(boolean b) { this.debugIntegrations = b; }

    public boolean isDebugStorage() { return debugStorage || debugMode; }
    public void setDebugStorage(boolean b) { this.debugStorage = b; }

    public boolean isDebugAuth() { return debugAuth || debugMode; }
    public void setDebugAuth(boolean b) { this.debugAuth = b; }

    // === Web Dashboard ===
    public boolean isWebDashboardEnabled() { return webDashboardEnabled; }
    public void setWebDashboardEnabled(boolean b) { this.webDashboardEnabled = b; }

    public int getWebDashboardPort() { return webDashboardPort; }
    public void setWebDashboardPort(int p) { this.webDashboardPort = p; }

    public String getWebDashboardHost() { return webDashboardHost; }
    public void setWebDashboardHost(String h) { this.webDashboardHost = h; }

    public String getWebDashboardSecret() { return webDashboardSecret; }
    public void setWebDashboardSecret(String s) { this.webDashboardSecret = s; }

    public boolean isWebDashboardHttps() { return webDashboardHttps; }
    public void setWebDashboardHttps(boolean b) { this.webDashboardHttps = b; }

    public String getWebDashboardSslCert() { return webDashboardSslCert; }
    public void setWebDashboardSslCert(String c) { this.webDashboardSslCert = c; }

    public String getWebDashboardSslKey() { return webDashboardSslKey; }
    public void setWebDashboardSslKey(String k) { this.webDashboardSslKey = k; }

    // === Trusted Device ===
    public boolean isTrustedDeviceEnabled() { return trustedDeviceEnabled; }
    public void setTrustedDeviceEnabled(boolean b) { this.trustedDeviceEnabled = b; }

    public int getTrustedDeviceTtlDays() { return trustedDeviceTtlDays; }
    public void setTrustedDeviceTtlDays(int d) { this.trustedDeviceTtlDays = d; }

    public int getMaxTrustedDevicesPerPlayer() { return maxTrustedDevicesPerPlayer; }
    public void setMaxTrustedDevicesPerPlayer(int m) { this.maxTrustedDevicesPerPlayer = m; }

    // === Login Notifications ===
    public boolean isLoginNotificationsEnabled() { return loginNotificationsEnabled; }
    public void setLoginNotificationsEnabled(boolean b) { this.loginNotificationsEnabled = b; }

    public boolean isLoginNotifyOnNewIp() { return loginNotifyOnNewIp; }
    public void setLoginNotifyOnNewIp(boolean b) { this.loginNotifyOnNewIp = b; }

    public boolean isLoginNotifyOnNewDevice() { return loginNotifyOnNewDevice; }
    public void setLoginNotifyOnNewDevice(boolean b) { this.loginNotifyOnNewDevice = b; }

    public boolean isLoginNotifyOnSessionRestored() { return loginNotifyOnSessionRestored; }
    public void setLoginNotifyOnSessionRestored(boolean b) { this.loginNotifyOnSessionRestored = b; }

    // === Redis Multi-Server Sync ===
    public boolean isRedisSyncEnabled() { return redisSyncEnabled; }
    public void setRedisSyncEnabled(boolean b) { this.redisSyncEnabled = b; }

    public String getRedisHost() { return redisHost; }
    public void setRedisHost(String h) { this.redisHost = h; }

    public int getRedisPort() { return redisPort; }
    public void setRedisPort(int p) { this.redisPort = p; }

    public String getRedisPassword() { return redisPassword; }
    public void setRedisPassword(String p) { this.redisPassword = p; }

    public int getRedisDatabase() { return redisDatabase; }
    public void setRedisDatabase(int d) { this.redisDatabase = d; }

    public int getRedisMaxConnections() { return redisMaxConnections; }
    public void setRedisMaxConnections(int c) { this.redisMaxConnections = c; }

    public int getRedisMaxIdle() { return redisMaxIdle; }
    public void setRedisMaxIdle(int i) { this.redisMaxIdle = i; }

    public int getRedisMinIdle() { return redisMinIdle; }
    public void setRedisMinIdle(int i) { this.redisMinIdle = i; }

    public int getRedisTimeoutMs() { return redisTimeoutMs; }
    public void setRedisTimeoutMs(int t) { this.redisTimeoutMs = t; }

    public boolean isRedisSSLEnabled() { return redisSSLEnabled; }
    public void setRedisSSLEnabled(boolean b) { this.redisSSLEnabled = b; }

    public String getServerName() { return serverName; }
    public void setServerName(String n) { this.serverName = n; }

    // === GDPR Compliance ===
    public int getDeletionGracePeriodDays() { return deletionGracePeriodDays; }
    public void setDeletionGracePeriodDays(int d) { this.deletionGracePeriodDays = d; }

    public boolean isGdprDataExportEnabled() { return gdprDataExportEnabled; }
    public void setGdprDataExportEnabled(boolean b) { this.gdprDataExportEnabled = b; }

    public boolean isGdprRightToBeForgottenEnabled() { return gdprRightToBeForgottenEnabled; }
    public void setGdprRightToBeForgottenEnabled(boolean b) { this.gdprRightToBeForgottenEnabled = b; }

    public int getDataRetentionDays() { return dataRetentionDays; }
    public void setDataRetentionDays(int d) { this.dataRetentionDays = d; }

    // === Social Authentication (OAuth2) ===
    public boolean isDiscordAuthEnabled() { return discordAuthEnabled; }
    public void setDiscordAuthEnabled(boolean b) { this.discordAuthEnabled = b; }

    public String getDiscordClientId() { return discordClientId; }
    public void setDiscordClientId(String id) { this.discordClientId = id; }

    public String getDiscordClientSecret() { return discordClientSecret; }
    public void setDiscordClientSecret(String s) { this.discordClientSecret = s; }

    public String getDiscordRedirectUri() { return discordRedirectUri; }
    public void setDiscordRedirectUri(String u) { this.discordRedirectUri = u; }

    public boolean isGoogleAuthEnabled() { return googleAuthEnabled; }
    public void setGoogleAuthEnabled(boolean b) { this.googleAuthEnabled = b; }

    public String getGoogleClientId() { return googleClientId; }
    public void setGoogleClientId(String id) { this.googleClientId = id; }

    public String getGoogleClientSecret() { return googleClientSecret; }
    public void setGoogleClientSecret(String s) { this.googleClientSecret = s; }

    public String getGoogleRedirectUri() { return googleRedirectUri; }
    public void setGoogleRedirectUri(String u) { this.googleRedirectUri = u; }

    public boolean isMicrosoftAuthEnabled() { return microsoftAuthEnabled; }
    public void setMicrosoftAuthEnabled(boolean b) { this.microsoftAuthEnabled = b; }

    public String getMicrosoftClientId() { return microsoftClientId; }
    public void setMicrosoftClientId(String id) { this.microsoftClientId = id; }

    public String getMicrosoftClientSecret() { return microsoftClientSecret; }
    public void setMicrosoftClientSecret(String s) { this.microsoftClientSecret = s; }

    public String getMicrosoftRedirectUri() { return microsoftRedirectUri; }
    public void setMicrosoftRedirectUri(String u) { this.microsoftRedirectUri = u; }

    public boolean isAccountMergeEnabled() { return accountMergeEnabled; }
    public void setAccountMergeEnabled(boolean b) { this.accountMergeEnabled = b; }

    public int getOauthStateExpirationMinutes() { return oauthStateExpirationMinutes; }
    public void setOauthStateExpirationMinutes(int m) { this.oauthStateExpirationMinutes = m; }
}