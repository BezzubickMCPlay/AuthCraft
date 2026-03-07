// com/authcraft/core/service/MobileAppService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.Session;
import com.authcraft.core.model.TwoFactorMethod;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Service for mobile app integration.
 * Provides push notifications, quick approval/deny, account management, and server status monitoring.
 */
public class MobileAppService {
    private static final Logger logger = Logger.getLogger(MobileAppService.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();
    
    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final StorageProvider storage;
    private final AuditService auditService;
    
    // Registered mobile devices
    private final Map<UUID, List<MobileDevice>> playerDevices = new ConcurrentHashMap<>();
    // Pending approval requests
    private final Map<String, ApprovalRequest> pendingApprovals = new ConcurrentHashMap<>();
    // Push notification providers
    private final Map<DeviceType, PushProvider> pushProviders = new ConcurrentHashMap<>();
    // Server status cache
    private volatile ServerStatus currentStatus;
    // Scheduled executor for cleanup
    private ScheduledExecutorService scheduler;
    
    public MobileAppService(AuthCraftConfig config, PlatformAdapter platform, 
                           StorageProvider storage, AuditService auditService) {
        this.config = config;
        this.platform = platform;
        this.storage = storage;
        this.auditService = auditService;
        this.currentStatus = new ServerStatus();
    }
    
    /**
     * Initialize the mobile app service.
     */
    public void initialize() {
        scheduler = Executors.newScheduledThreadPool(2);
        
        // Schedule cleanup of expired approvals
        scheduler.scheduleAtFixedRate(this::cleanupExpiredApprovals, 1, 1, TimeUnit.MINUTES);
        
        // Schedule server status updates
        scheduler.scheduleAtFixedRate(this::updateServerStatus, 5, 30, TimeUnit.SECONDS);
        
        // Initialize push providers
        initializePushProviders();
        
        logger.info("MobileAppService initialized");
    }
    
    /**
     * Shutdown the mobile app service.
     */
    public void shutdown() {
        if (scheduler != null) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
            }
        }
        logger.info("MobileAppService shutdown complete");
    }
    
    // ==================== DEVICE REGISTRATION ====================
    
    /**
     * Register a mobile device for a player.
     */
    public CompletableFuture<DeviceRegistrationResult> registerDevice(UUID playerUuid, 
            DeviceType deviceType, String deviceToken, String deviceName) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new DeviceRegistrationResult(false, null, "Account not found");
            }
            
            Account account = optAccount.get();
            
            // Generate device ID
            String deviceId = generateDeviceId();
            
            // Create device record
            MobileDevice device = new MobileDevice(
                deviceId, playerUuid, deviceType, deviceToken, 
                deviceName, System.currentTimeMillis(), true
            );
            
            // Add to player's devices
            playerDevices.computeIfAbsent(playerUuid, k -> new ArrayList<>()).add(device);
            
            // Log audit event
            String playerIp = platform.getPlayerIp(playerUuid);
            auditService.log(AuditEventType.CUSTOM, playerUuid, account.getUsername(),
                playerIp != null ? playerIp : "unknown",
                "Mobile device registered: " + deviceName + " (" + deviceType + ")");
            
            logger.info("Mobile device registered for " + account.getUsername() + ": " + deviceName);
            
            return new DeviceRegistrationResult(true, deviceId, "Device registered successfully");
        });
    }
    
    /**
     * Unregister a mobile device.
     */
    public CompletableFuture<Boolean> unregisterDevice(UUID playerUuid, String deviceId) {
        return CompletableFuture.supplyAsync(() -> {
            List<MobileDevice> devices = playerDevices.get(playerUuid);
            if (devices == null) {
                return false;
            }
            
            boolean removed = devices.removeIf(d -> d.getDeviceId().equals(deviceId));
            if (removed) {
                logger.info("Mobile device unregistered: " + deviceId);
            }
            return removed;
        });
    }
    
    /**
     * Get all registered devices for a player.
     */
    public List<MobileDevice> getPlayerDevices(UUID playerUuid) {
        return playerDevices.getOrDefault(playerUuid, Collections.emptyList());
    }
    
    // ==================== PUSH NOTIFICATIONS ====================
    
    /**
     * Send a push notification for login approval.
     */
    public CompletableFuture<PushResult> sendLoginApprovalNotification(UUID playerUuid, 
            String username, String ipAddress, String location, String deviceInfo) {
        return CompletableFuture.supplyAsync(() -> {
            List<MobileDevice> devices = playerDevices.get(playerUuid);
            if (devices == null || devices.isEmpty()) {
                return new PushResult(false, "No registered devices", Collections.emptyList());
            }
            
            // Create approval request
            String approvalId = generateApprovalId();
            ApprovalRequest request = new ApprovalRequest(
                approvalId, playerUuid, username, ipAddress, 
                location, deviceInfo, System.currentTimeMillis(), 
                System.currentTimeMillis() + (5 * 60 * 1000) // 5 minute expiry
            );
            pendingApprovals.put(approvalId, request);
            
            // Send push to all active devices
            List<CompletableFuture<PushDeliveryResult>> pushFutures = new ArrayList<>();
            for (MobileDevice device : devices) {
                if (device.isActive()) {
                    pushFutures.add(sendPushNotification(device, 
                        buildLoginApprovalMessage(request), "login_approval"));
                }
            }
            
            // Wait for all pushes
            List<PushDeliveryResult> results = new ArrayList<>();
            for (CompletableFuture<PushDeliveryResult> future : pushFutures) {
                try {
                    results.add(future.get(10, TimeUnit.SECONDS));
                } catch (Exception e) {
                    results.add(new PushDeliveryResult(false, "Push failed: " + e.getMessage()));
                }
            }
            
            boolean anySuccess = results.stream().anyMatch(PushDeliveryResult::isSuccess);
            return new PushResult(anySuccess, 
                anySuccess ? "Notification sent" : "All push notifications failed", results);
        });
    }
    
    /**
     * Send a security alert notification.
     */
    public CompletableFuture<Boolean> sendSecurityAlert(UUID playerUuid, String title, String message) {
        return CompletableFuture.supplyAsync(() -> {
            List<MobileDevice> devices = playerDevices.get(playerUuid);
            if (devices == null || devices.isEmpty()) {
                return false;
            }
            
            boolean anySuccess = false;
            for (MobileDevice device : devices) {
                if (device.isActive()) {
                    try {
                        PushDeliveryResult result = sendPushNotification(device, 
                            Map.of("title", title, "message", message, "type", "security_alert"),
                            "security_alert").get(5, TimeUnit.SECONDS);
                        if (result.isSuccess()) {
                            anySuccess = true;
                        }
                    } catch (Exception e) {
                        logger.warning("Failed to send security alert to device: " + e.getMessage());
                    }
                }
            }
            return anySuccess;
        });
    }
    
    /**
     * Send a push notification to a specific device.
     */
    private CompletableFuture<PushDeliveryResult> sendPushNotification(MobileDevice device, 
            Map<String, Object> payload, String type) {
        return CompletableFuture.supplyAsync(() -> {
            PushProvider provider = pushProviders.get(device.getDeviceType());
            if (provider == null) {
                return new PushDeliveryResult(false, "No push provider for device type");
            }
            
            try {
                return provider.sendPush(device.getDeviceToken(), payload, type);
            } catch (Exception e) {
                logger.warning("Push notification failed: " + e.getMessage());
                return new PushDeliveryResult(false, e.getMessage());
            }
        });
    }
    
    private CompletableFuture<PushDeliveryResult> sendPushNotification(MobileDevice device, 
            Object payload, String type) {
        if (payload instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) payload;
            return sendPushNotification(device, map, type);
        }
        Map<String, Object> map = new HashMap<>();
        map.put("data", payload);
        map.put("type", type);
        return sendPushNotification(device, map, type);
    }
    
    // ==================== QUICK APPROVAL/DENY ====================
    
    /**
     * Handle approval response from mobile app.
     */
    public CompletableFuture<ApprovalResponseResult> handleApprovalResponse(
            String approvalId, UUID playerUuid, boolean approved, String deviceId) {
        return CompletableFuture.supplyAsync(() -> {
            ApprovalRequest request = pendingApprovals.get(approvalId);
            if (request == null) {
                return new ApprovalResponseResult(false, "Approval request not found or expired");
            }
            
            if (!request.getPlayerUuid().equals(playerUuid)) {
                return new ApprovalResponseResult(false, "Invalid player for this approval");
            }
            
            if (request.isExpired()) {
                pendingApprovals.remove(approvalId);
                return new ApprovalResponseResult(false, "Approval request has expired");
            }
            
            // Remove the approval request
            pendingApprovals.remove(approvalId);
            
            // Log the decision
            storage.getAccount(playerUuid).thenAccept(optAccount -> {
                optAccount.ifPresent(account -> {
                    String action = approved ? "approved" : "denied";
                    auditService.log(AuditEventType.CUSTOM, playerUuid, account.getUsername(),
                        request.getIpAddress(),
                        "Login " + action + " via mobile app (device: " + deviceId + ")");
                });
            });
            
            logger.info("Login " + (approved ? "approved" : "denied") + " for " + request.getUsername() + 
                " from device " + deviceId);
            
            return new ApprovalResponseResult(true, 
                approved ? "Login approved" : "Login denied", approved, request);
        });
    }
    
    /**
     * Get pending approval requests for a player.
     */
    public List<ApprovalRequest> getPendingApprovals(UUID playerUuid) {
        List<ApprovalRequest> result = new ArrayList<>();
        for (ApprovalRequest request : pendingApprovals.values()) {
            if (request.getPlayerUuid().equals(playerUuid) && !request.isExpired()) {
                result.add(request);
            }
        }
        return result;
    }
    
    /**
     * Check if there's a pending approval for a player from a specific IP.
     */
    public Optional<ApprovalRequest> getPendingApproval(UUID playerUuid, String ipAddress) {
        for (ApprovalRequest request : pendingApprovals.values()) {
            if (request.getPlayerUuid().equals(playerUuid) && 
                request.getIpAddress().equals(ipAddress) && 
                !request.isExpired()) {
                return Optional.of(request);
            }
        }
        return Optional.empty();
    }
    
    // ==================== ACCOUNT MANAGEMENT ====================
    
    /**
     * Get account summary for mobile app.
     */
    public CompletableFuture<Optional<AccountSummary>> getAccountSummary(UUID playerUuid) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return Optional.empty();
            }
            
            Account account = optAccount.get();
            List<MobileDevice> devices = playerDevices.getOrDefault(playerUuid, Collections.emptyList());
            
            AccountSummary summary = new AccountSummary(
                playerUuid,
                account.getUsername(),
                account.getEmail(),
                account.getEnabledTwoFactorMethods(),
                account.isRegistered(),
                account.isLocked(),
                account.getFailedLoginAttempts(),
                account.getLastLoginDate() != null ? account.getLastLoginDate().toEpochMilli() : 0,
                account.getLastLoginIp(),
                devices.size(),
                calculateSecurityScore(account)
            );
            
            return Optional.of(summary);
        });
    }
    
    /**
     * Update account settings from mobile app.
     */
    public CompletableFuture<SettingsUpdateResult> updateAccountSettings(UUID playerUuid, 
            Map<String, Object> settings) {
        return storage.getAccount(playerUuid).thenCompose(optAccount -> {
            if (optAccount.isEmpty()) {
                return CompletableFuture.completedFuture(
                    new SettingsUpdateResult(false, "Account not found"));
            }
            
            Account account = optAccount.get();
            List<String> changes = new ArrayList<>();
            
            // Process settings updates
            if (settings.containsKey("email")) {
                String newEmail = (String) settings.get("email");
                if (!newEmail.equals(account.getEmail())) {
                    account.setEmail(newEmail);
                    changes.add("email updated");
                }
            }
            
            // Save if there were changes
            if (!changes.isEmpty()) {
                return storage.saveAccount(account).thenApply(v -> {
                    String ip = platform.getPlayerIp(playerUuid);
                    auditService.log(AuditEventType.CUSTOM, playerUuid, account.getUsername(),
                        ip != null ? ip : "unknown",
                        "Account settings updated via mobile: " + String.join(", ", changes));
                    return new SettingsUpdateResult(true, "Settings updated: " + String.join(", ", changes));
                });
            }
            
            return CompletableFuture.completedFuture(
                new SettingsUpdateResult(true, "No changes to apply"));
        });
    }
    
    /**
     * Change password from mobile app.
     */
    public CompletableFuture<PasswordChangeResult> changePassword(UUID playerUuid, 
            String currentPassword, String newPassword) {
        // This would integrate with the existing AuthService
        // For now, return a placeholder
        return CompletableFuture.completedFuture(
            new PasswordChangeResult(false, "Password change requires server-side validation"));
    }
    
    /**
     * Enable/disable two-factor authentication from mobile app.
     */
    public CompletableFuture<TwoFactorResult> toggleTwoFactor(UUID playerUuid, 
            TwoFactorMethod method, boolean enable) {
        return storage.getAccount(playerUuid).thenCompose(optAccount -> {
            if (optAccount.isEmpty()) {
                return CompletableFuture.completedFuture(
                    new TwoFactorResult(false, "Account not found"));
            }
            
            Account account = optAccount.get();
            
            if (enable) {
                if (account.getEnabledTwoFactorMethods().contains(method)) {
                    return CompletableFuture.completedFuture(
                        new TwoFactorResult(false, method + " is already enabled"));
                }
                account.getEnabledTwoFactorMethods().add(method);
            } else {
                account.getEnabledTwoFactorMethods().remove(method);
            }
            
            return storage.saveAccount(account).thenApply(v -> {
                String action = enable ? "enabled" : "disabled";
                String ip = platform.getPlayerIp(playerUuid);
                auditService.log(enable ? AuditEventType.TWO_FACTOR_ENABLE : AuditEventType.TWO_FACTOR_DISABLE,
                    playerUuid, account.getUsername(),
                    ip != null ? ip : "unknown",
                    method + " " + action + " via mobile app");
                return new TwoFactorResult(true, method + " " + action + " successfully");
            });
        });
    }
    
    // ==================== SERVER STATUS MONITORING ====================
    
    /**
     * Get current server status.
     */
    public ServerStatus getServerStatus() {
        return currentStatus;
    }
    
    /**
     * Update server status.
     */
    private void updateServerStatus() {
        try {
            int onlinePlayers = platform.getOnlinePlayers().size();
            long usedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            long maxMemory = Runtime.getRuntime().maxMemory();
            
            currentStatus = new ServerStatus(
                onlinePlayers,
                onlinePlayers, // maxPlayers not available, use current count
                20.0, // default TPS (not available from platform)
                usedMemory,
                maxMemory,
                System.currentTimeMillis(),
                true
            );
        } catch (Exception e) {
            logger.warning("Failed to update server status: " + e.getMessage());
        }
    }
    
    /**
     * Get detailed server information for mobile app.
     */
    public ServerInfo getServerInfo() {
        return new ServerInfo(
            config.getServerName(),
            "Unknown", // server version not available from platform
            currentStatus,
            platform.getOnlinePlayers().size(),
            platform.getOnlinePlayers().size(), // maxPlayers not available
            System.currentTimeMillis()
        );
    }
    
    // ==================== HELPER METHODS ====================
    
    private void initializePushProviders() {
        // Firebase/APNs would be configured here
        // For now, use a mock provider
        pushProviders.put(DeviceType.IOS, new MockPushProvider("APNs"));
        pushProviders.put(DeviceType.ANDROID, new MockPushProvider("FCM"));
    }
    
    private String generateDeviceId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private String generateApprovalId() {
        byte[] bytes = new byte[8];
        RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private void cleanupExpiredApprovals() {
        long now = System.currentTimeMillis();
        pendingApprovals.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
    
    private Map<String, Object> buildLoginApprovalMessage(ApprovalRequest request) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "login_approval");
        message.put("approval_id", request.getApprovalId());
        message.put("username", request.getUsername());
        message.put("ip_address", request.getIpAddress());
        message.put("location", request.getLocation());
        message.put("device_info", request.getDeviceInfo());
        message.put("timestamp", request.getCreatedAt());
        message.put("expires_at", request.getExpiresAt());
        return message;
    }
    
    private int calculateSecurityScore(Account account) {
        int score = 0;
        
        // Base score for having an account
        score += 20;
        
        // Two-factor authentication
        if (!account.getEnabledTwoFactorMethods().isEmpty()) {
            score += 30;
            if (account.getEnabledTwoFactorMethods().size() > 1) {
                score += 10;
            }
        }
        
        // Email verified
        if (account.getEmail() != null && !account.getEmail().isEmpty()) {
            score += 15;
        }
        
        // Registered (not guest)
        if (account.isRegistered()) {
            score += 15;
        }
        
        // No recent failed attempts
        if (account.getFailedLoginAttempts() == 0) {
            score += 10;
        }
        
        // Not locked
        if (!account.isLocked()) {
            score += 10;
        }
        
        return Math.min(100, score);
    }
    
    // ==================== INNER CLASSES ====================
    
    /**
     * Represents a registered mobile device.
     */
    public static class MobileDevice {
        private final String deviceId;
        private final UUID playerUuid;
        private final DeviceType deviceType;
        private final String deviceToken;
        private final String deviceName;
        private final long registeredAt;
        private final boolean active;
        
        public MobileDevice(String deviceId, UUID playerUuid, DeviceType deviceType, 
                String deviceToken, String deviceName, long registeredAt, boolean active) {
            this.deviceId = deviceId;
            this.playerUuid = playerUuid;
            this.deviceType = deviceType;
            this.deviceToken = deviceToken;
            this.deviceName = deviceName;
            this.registeredAt = registeredAt;
            this.active = active;
        }
        
        public String getDeviceId() { return deviceId; }
        public UUID getPlayerUuid() { return playerUuid; }
        public DeviceType getDeviceType() { return deviceType; }
        public String getDeviceToken() { return deviceToken; }
        public String getDeviceName() { return deviceName; }
        public long getRegisteredAt() { return registeredAt; }
        public boolean isActive() { return active; }
    }
    
    /**
     * Device type enumeration.
     */
    public enum DeviceType {
        IOS,
        ANDROID
    }
    
    /**
     * Approval request for login.
     */
    public static class ApprovalRequest {
        private final String approvalId;
        private final UUID playerUuid;
        private final String username;
        private final String ipAddress;
        private final String location;
        private final String deviceInfo;
        private final long createdAt;
        private final long expiresAt;
        
        public ApprovalRequest(String approvalId, UUID playerUuid, String username, 
                String ipAddress, String location, String deviceInfo, 
                long createdAt, long expiresAt) {
            this.approvalId = approvalId;
            this.playerUuid = playerUuid;
            this.username = username;
            this.ipAddress = ipAddress;
            this.location = location;
            this.deviceInfo = deviceInfo;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }
        
        public String getApprovalId() { return approvalId; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getUsername() { return username; }
        public String getIpAddress() { return ipAddress; }
        public String getLocation() { return location; }
        public String getDeviceInfo() { return deviceInfo; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }
    
    /**
     * Server status information.
     */
    public static class ServerStatus {
        private final int onlinePlayers;
        private final int maxPlayers;
        private final double tps;
        private final long usedMemory;
        private final long maxMemory;
        private final long timestamp;
        private final boolean online;
        
        public ServerStatus() {
            this(0, 0, 20.0, 0, 0, System.currentTimeMillis(), true);
        }
        
        public ServerStatus(int onlinePlayers, int maxPlayers, double tps, 
                long usedMemory, long maxMemory, long timestamp, boolean online) {
            this.onlinePlayers = onlinePlayers;
            this.maxPlayers = maxPlayers;
            this.tps = tps;
            this.usedMemory = usedMemory;
            this.maxMemory = maxMemory;
            this.timestamp = timestamp;
            this.online = online;
        }
        
        public int getOnlinePlayers() { return onlinePlayers; }
        public int getMaxPlayers() { return maxPlayers; }
        public double getTps() { return tps; }
        public long getUsedMemory() { return usedMemory; }
        public long getMaxMemory() { return maxMemory; }
        public long getTimestamp() { return timestamp; }
        public boolean isOnline() { return online; }
        
        public double getMemoryUsagePercent() {
            if (maxMemory == 0) return 0;
            return (double) usedMemory / maxMemory * 100;
        }
    }
    
    /**
     * Server information for mobile app.
     */
    public static class ServerInfo {
        private final String serverName;
        private final String serverVersion;
        private final ServerStatus status;
        private final int onlineCount;
        private final int maxPlayers;
        private final long serverTime;
        
        public ServerInfo(String serverName, String serverVersion, ServerStatus status, 
                int onlineCount, int maxPlayers, long serverTime) {
            this.serverName = serverName;
            this.serverVersion = serverVersion;
            this.status = status;
            this.onlineCount = onlineCount;
            this.maxPlayers = maxPlayers;
            this.serverTime = serverTime;
        }
        
        public String getServerName() { return serverName; }
        public String getServerVersion() { return serverVersion; }
        public ServerStatus getStatus() { return status; }
        public int getOnlineCount() { return onlineCount; }
        public int getMaxPlayers() { return maxPlayers; }
        public long getServerTime() { return serverTime; }
    }
    
    /**
     * Account summary for mobile app.
     */
    public static class AccountSummary {
        private final UUID uuid;
        private final String username;
        private final String email;
        private final Set<TwoFactorMethod> twoFactorMethods;
        private final boolean registered;
        private final boolean locked;
        private final int failedAttempts;
        private final long lastLogin;
        private final String lastIp;
        private final int deviceCount;
        private final int securityScore;
        
        public AccountSummary(UUID uuid, String username, String email, 
                Set<TwoFactorMethod> twoFactorMethods, boolean registered, boolean locked,
                int failedAttempts, long lastLogin, String lastIp, 
                int deviceCount, int securityScore) {
            this.uuid = uuid;
            this.username = username;
            this.email = email;
            this.twoFactorMethods = twoFactorMethods;
            this.registered = registered;
            this.locked = locked;
            this.failedAttempts = failedAttempts;
            this.lastLogin = lastLogin;
            this.lastIp = lastIp;
            this.deviceCount = deviceCount;
            this.securityScore = securityScore;
        }
        
        public UUID getUuid() { return uuid; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public Set<TwoFactorMethod> getTwoFactorMethods() { return twoFactorMethods; }
        public boolean isRegistered() { return registered; }
        public boolean isLocked() { return locked; }
        public int getFailedAttempts() { return failedAttempts; }
        public long getLastLogin() { return lastLogin; }
        public String getLastIp() { return lastIp; }
        public int getDeviceCount() { return deviceCount; }
        public int getSecurityScore() { return securityScore; }
    }
    
    // Result classes
    
    public static class DeviceRegistrationResult {
        private final boolean success;
        private final String deviceId;
        private final String message;
        
        public DeviceRegistrationResult(boolean success, String deviceId, String message) {
            this.success = success;
            this.deviceId = deviceId;
            this.message = message;
        }
        
        public boolean isSuccess() { return success; }
        public String getDeviceId() { return deviceId; }
        public String getMessage() { return message; }
    }
    
    public static class PushResult {
        private final boolean success;
        private final String message;
        private final List<PushDeliveryResult> deliveryResults;
        
        public PushResult(boolean success, String message, List<PushDeliveryResult> deliveryResults) {
            this.success = success;
            this.message = message;
            this.deliveryResults = deliveryResults;
        }
        
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public List<PushDeliveryResult> getDeliveryResults() { return deliveryResults; }
    }
    
    public static class PushDeliveryResult {
        private final boolean success;
        private final String message;
        
        public PushDeliveryResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
        
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }
    
    public static class ApprovalResponseResult {
        private final boolean success;
        private final String message;
        private final boolean approved;
        private final ApprovalRequest request;
        
        public ApprovalResponseResult(boolean success, String message) {
            this(success, message, false, null);
        }
        
        public ApprovalResponseResult(boolean success, String message, 
                boolean approved, ApprovalRequest request) {
            this.success = success;
            this.message = message;
            this.approved = approved;
            this.request = request;
        }
        
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public boolean isApproved() { return approved; }
        public ApprovalRequest getRequest() { return request; }
    }
    
    public static class SettingsUpdateResult {
        private final boolean success;
        private final String message;
        
        public SettingsUpdateResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
        
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }
    
    public static class PasswordChangeResult {
        private final boolean success;
        private final String message;
        
        public PasswordChangeResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
        
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }
    
    public static class TwoFactorResult {
        private final boolean success;
        private final String message;
        
        public TwoFactorResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
        
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }
    
    // ==================== PUSH PROVIDER INTERFACE ====================
    
    /**
     * Interface for push notification providers.
     */
    public interface PushProvider {
        PushDeliveryResult sendPush(String deviceToken, Map<String, Object> payload, String type);
    }
    
    /**
     * Mock push provider for testing.
     */
    private static class MockPushProvider implements PushProvider {
        private final String name;
        
        public MockPushProvider(String name) {
            this.name = name;
        }
        
        @Override
        public PushDeliveryResult sendPush(String deviceToken, Map<String, Object> payload, String type) {
            // In production, this would call actual FCM/APNs APIs
            logger.fine("Mock push sent via " + name + " to " + deviceToken + ": " + type);
            return new PushDeliveryResult(true, "Push sent via " + name);
        }
    }
}
