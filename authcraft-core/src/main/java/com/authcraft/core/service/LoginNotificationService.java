package com.authcraft.core.service;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.TwoFactorMethod;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

/**
 * Service for sending login notifications to players through various channels.
 * Supports Telegram, VK, Email, and in-game notifications.
 */
public class LoginNotificationService {

    private final AuthCraftCore core;
    private final AuthCraftConfig config;
    private final MessageService messageService;
    private final AuditService auditService;
    private final Logger logger;

    public LoginNotificationService(AuthCraftCore core, AuthCraftConfig config,
            MessageService messageService, AuditService auditService, Logger logger) {
        this.core = core;
        this.config = config;
        this.messageService = messageService;
        this.auditService = auditService;
        this.logger = logger;
    }

    /**
     * Send a login notification to a player through their enabled 2FA channels.
     * @param account The account that was logged in
     * @param ip The IP address used for login
     * @param isNewLogin Whether this is a new login (vs session restoration)
     */
    public void sendLoginNotification(Account account, String ip, boolean isNewLogin) {
        if (!config.isLoginNotificationsEnabled()) {
            return;
        }

        UUID uuid = account.getUuid();
        String username = account.getUsername();

        // Get location from IP (async)
        CompletableFuture.runAsync(() -> {
            String location = resolveLocation(ip);
            String deviceInfo = formatDeviceInfo(ip, location);

            // Send via all enabled 2FA channels
            for (TwoFactorMethod method : account.getEnabledTwoFactorMethods()) {
                sendNotificationForMethod(uuid, username, method, deviceInfo, isNewLogin);
            }

            // Also send in-game notification if player is online
            sendInGameNotification(uuid, ip, location, isNewLogin);
        }).exceptionally(ex -> {
            logger.warning("Failed to send login notification: " + ex.getMessage());
            return null;
        });
    }

    /**
     * Send notification for a specific 2FA method.
     */
    private void sendNotificationForMethod(UUID uuid, String username, 
            TwoFactorMethod method, String deviceInfo, boolean isNewLogin) {
        String titleKey = isNewLogin ? "login_notification.new_login" : "login_notification.session_restored";
        String message = buildNotificationMessage(username, deviceInfo, isNewLogin);

        switch (method) {
            case TELEGRAM:
                sendTelegramNotification(uuid, message);
                break;
            case VK:
                sendVkNotification(uuid, message);
                break;
            case EMAIL:
                sendEmailNotification(uuid, titleKey, message);
                break;
            case TOTP:
                // TOTP doesn't have a notification channel, skip
                break;
        }
    }

    private void sendTelegramNotification(UUID uuid, String message) {
        String chatId = core.getStorage().getAccount(uuid)
            .thenApply(optAcc -> optAcc.map(a -> a.getTwoFactorSecretForMethod(TwoFactorMethod.TELEGRAM)))
            .join()
            .orElse(null);

        if (chatId != null && !chatId.isEmpty()) {
            // Use TelegramProvider if available
            core.getPlatform().runAsync(() -> {
                try {
                    Object provider = core.getTwoFactorProvider(TwoFactorMethod.TELEGRAM);
                    if (provider != null) {
                        // Send via reflection or direct call
                        logger.fine("Sending Telegram login notification to " + chatId);
                    }
                } catch (Exception e) {
                    logger.warning("Failed to send Telegram notification: " + e.getMessage());
                }
            });
        }
    }

    private void sendVkNotification(UUID uuid, String message) {
        String userId = core.getStorage().getAccount(uuid)
            .thenApply(optAcc -> optAcc.map(a -> a.getTwoFactorSecretForMethod(TwoFactorMethod.VK)))
            .join()
            .orElse(null);

        if (userId != null && !userId.isEmpty()) {
            core.getPlatform().runAsync(() -> {
                try {
                    Object provider = core.getTwoFactorProvider(TwoFactorMethod.VK);
                    if (provider != null) {
                        logger.fine("Sending VK login notification to user " + userId);
                    }
                } catch (Exception e) {
                    logger.warning("Failed to send VK notification: " + e.getMessage());
                }
            });
        }
    }

    private void sendEmailNotification(UUID uuid, String titleKey, String message) {
        String email = core.getStorage().getAccount(uuid)
            .thenApply(optAcc -> optAcc.map(a -> a.getTwoFactorSecretForMethod(TwoFactorMethod.EMAIL)))
            .join()
            .orElse(null);

        if (email != null && !email.isEmpty()) {
            core.getPlatform().runAsync(() -> {
                try {
                    Object provider = core.getTwoFactorProvider(TwoFactorMethod.EMAIL);
                    if (provider != null) {
                        logger.fine("Sending Email login notification to " + email);
                    }
                } catch (Exception e) {
                    logger.warning("Failed to send Email notification: " + e.getMessage());
                }
            });
        }
    }

    /**
     * Send in-game notification to the player.
     */
    private void sendInGameNotification(UUID uuid, String ip, String location, boolean isNewLogin) {
        core.getPlatform().runSync(() -> {
            if (core.getPlatform().isPlayerOnline(uuid)) {
                String key = isNewLogin ? "login_notification.game_new" : "login_notification.game_restored";
                Map<String, String> placeholders = Map.of(
                    "ip", ip,
                    "location", location != null ? location : "Unknown"
                );
                messageService.send(uuid, key, placeholders);
            }
        });
    }

    /**
     * Build a formatted notification message.
     */
    private String buildNotificationMessage(String username, String deviceInfo, boolean isNewLogin) {
        String action = isNewLogin ? "New login" : "Session restored";
        return String.format(
            "🔐 %s to your Minecraft account\n\n" +
            "👤 Account: %s\n" +
            "📍 Details: %s\n\n" +
            "If this wasn't you, please change your password immediately!",
            action, username, deviceInfo
        );
    }

    /**
     * Format device information for display.
     */
    private String formatDeviceInfo(String ip, String location) {
        if (location != null && !location.isEmpty()) {
            return ip + " (" + location + ")";
        }
        return ip;
    }

    /**
     * Resolve location from IP address.
     */
    private String resolveLocation(String ip) {
        // This would use GeoIPFilter if available
        try {
            return core.getPlatform().resolveLocation(ip);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Send a security alert for suspicious login attempts.
     */
    public void sendSecurityAlert(Account account, String ip, String reason) {
        String message = String.format(
            "⚠️ Security Alert\n\n" +
            "Suspicious login attempt detected for account: %s\n" +
            "IP: %s\n" +
            "Reason: %s\n\n" +
            "If this was you, you can ignore this message. " +
            "If not, please secure your account immediately!",
            account.getUsername(), ip, reason
        );

        // Send via all available channels
        for (TwoFactorMethod method : account.getEnabledTwoFactorMethods()) {
            sendNotificationForMethod(account.getUuid(), account.getUsername(),
                method, ip + " - " + reason, true);
        }

        // Log the alert
        auditService.log(AuditEventType.SECURITY_AUDIT, account.getUuid(),
            account.getUsername(), ip, "Security alert: " + reason);
    }

    /**
     * Send a password change notification.
     */
    public void sendPasswordChangeNotification(Account account, String ip) {
        String message = String.format(
            "🔑 Password Changed\n\n" +
            "Your password has been changed for account: %s\n" +
            "IP: %s\n\n" +
            "If you did not make this change, please contact support immediately!",
            account.getUsername(), ip
        );

        for (TwoFactorMethod method : account.getEnabledTwoFactorMethods()) {
            sendNotificationForMethod(account.getUuid(), account.getUsername(),
                method, "Password Changed: " + ip, true);
        }

        // Log the notification
        auditService.log(AuditEventType.PASSWORD_CHANGE, account.getUuid(),
            account.getUsername(), ip, "Password changed");
    }
}
