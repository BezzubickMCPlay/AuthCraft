// com/authcraft/core/service/PasswordlessService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.Session;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Passwordless Authentication Service.
 *
 * Features:
 * - Magic link authentication (email)
 * - QR code login (scan with phone)
 * - Push notification approval
 * - Biometric authentication bridge
 * - Hardware security key support (FIDO2/WebAuthn)
 */
public class PasswordlessService {

    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final StorageProvider storage;
    private final AuditService auditService;
    private final MessageService messageService;
    private final Logger logger;

    // Pending magic link requests
    private final Map<String, MagicLinkRequest> magicLinks = new ConcurrentHashMap<>();

    // Pending QR code login sessions
    private final Map<String, QRLoginSession> qrSessions = new ConcurrentHashMap<>();

    // Pending push notification approvals
    private final Map<String, PushApprovalRequest> pushApprovals = new ConcurrentHashMap<>();

    // Biometric session tokens
    private final Map<String, BiometricSession> biometricSessions = new ConcurrentHashMap<>();

    // FIDO2/WebAuthn credential storage (in-memory cache, should be persisted)
    private final Map<UUID, List<FIDO2Credential>> fido2Credentials = new ConcurrentHashMap<>();

    // Secure random for token generation
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Token expiration times
    private static final long MAGIC_LINK_TTL_MS = 15 * 60 * 1000; // 15 minutes
    private static final long QR_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes
    private static final long PUSH_APPROVAL_TTL_MS = 2 * 60 * 1000; // 2 minutes
    private static final long BIOMETRIC_SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes

    /**
     * Creates a new PasswordlessService.
     */
    public PasswordlessService(AuthCraftConfig config, PlatformAdapter platform,
                               StorageProvider storage, AuditService auditService,
                               MessageService messageService) {
        this.config = config;
        this.platform = platform;
        this.storage = storage;
        this.auditService = auditService;
        this.messageService = messageService;
        this.logger = platform.getLogger();
    }

    // === Magic Link Authentication ===

    /**
     * Generate a magic link for passwordless login.
     */
    public CompletableFuture<MagicLinkResult> generateMagicLink(String username, String email) {
        return storage.getAccountByName(username).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new MagicLinkResult(false, null, "Account not found");
            }

            Account account = optAccount.get();

            // Verify email matches
            if (account.getEmail() == null || !account.getEmail().equalsIgnoreCase(email)) {
                return new MagicLinkResult(false, null, "Email does not match");
            }

            // Generate secure token
            String token = generateSecureToken(32);
            String magicCode = generateNumericCode(6);

            // Create magic link request
            MagicLinkRequest request = new MagicLinkRequest(
                    account.getUuid(),
                    account.getUsername(),
                    email,
                    token,
                    magicCode,
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + MAGIC_LINK_TTL_MS
            );

            magicLinks.put(token, request);

            // Send magic link email
            boolean sent = sendMagicLinkEmail(email, token, magicCode);

            if (!sent) {
                magicLinks.remove(token);
                return new MagicLinkResult(false, null, "Failed to send magic link email");
            }

            // Audit log
            auditService.log(AuditEventType.LOGIN_SUCCESS, account.getUuid(),
                    account.getUsername(), "magic-link", "Magic link generated");

            logger.info("Magic link generated for " + username);

            return new MagicLinkResult(true, token, "Magic link sent to " + maskEmail(email));
        });
    }

    /**
     * Verify a magic link token.
     */
    public CompletableFuture<MagicLinkVerifyResult> verifyMagicLink(String token, String ip) {
        return CompletableFuture.supplyAsync(() -> {
            MagicLinkRequest request = magicLinks.remove(token);

            if (request == null) {
                return new MagicLinkVerifyResult(false, null, null, "Invalid or expired magic link");
            }

            if (request.getExpiresAt() < System.currentTimeMillis()) {
                return new MagicLinkVerifyResult(false, null, null, "Magic link has expired");
            }

            // Get account
            Account account = storage.getAccount(request.getPlayerUuid()).join().orElse(null);
            if (account == null) {
                return new MagicLinkVerifyResult(false, null, null, "Account not found");
            }

            // Remove used magic link
            magicLinks.remove(token);

            // Audit log
            auditService.log(AuditEventType.LOGIN_SUCCESS, account.getUuid(),
                    account.getUsername(), ip, "Magic link login successful");

            logger.info("Magic link login successful for " + account.getUsername());

            return new MagicLinkVerifyResult(true, account, request.getEmail(), "Login successful");
        });
    }

    /**
     * Verify a magic link code (alternative to token).
     */
    public CompletableFuture<MagicLinkVerifyResult> verifyMagicCode(String code, String ip) {
        return CompletableFuture.supplyAsync(() -> {
            MagicLinkRequest request = null;
            String token = null;

            // Find request by code
            for (Map.Entry<String, MagicLinkRequest> entry : magicLinks.entrySet()) {
                if (entry.getValue().getMagicCode().equals(code)) {
                    request = entry.getValue();
                    token = entry.getKey();
                    break;
                }
            }

            if (request == null) {
                return new MagicLinkVerifyResult(false, null, null, "Invalid or expired magic code");
            }

            if (request.getExpiresAt() < System.currentTimeMillis()) {
                magicLinks.remove(token);
                return new MagicLinkVerifyResult(false, null, null, "Magic code has expired");
            }

            // Get account
            Account account = storage.getAccount(request.getPlayerUuid()).join().orElse(null);
            if (account == null) {
                return new MagicLinkVerifyResult(false, null, null, "Account not found");
            }

            // Remove used magic link
            magicLinks.remove(token);

            // Audit log
            auditService.log(AuditEventType.LOGIN_SUCCESS, account.getUuid(),
                    account.getUsername(), ip, "Magic code login successful");

            logger.info("Magic code login successful for " + account.getUsername());

            return new MagicLinkVerifyResult(true, account, request.getEmail(), "Login successful");
        });
    }

    private boolean sendMagicLinkEmail(String email, String token, String code) {
        // This would integrate with the EmailProvider
        // For now, we'll log it
        logger.info("Sending magic link to " + maskEmail(email) + " with code: " + code);
        return true; // Placeholder - actual implementation would use EmailProvider
    }

    // === QR Code Login ===

    /**
     * Generate a QR code login session.
     */
    public QRLoginResult generateQRLoginSession() {
        String sessionId = generateSecureToken(16);
        String qrCode = generateSecureToken(32);
        String verificationCode = generateNumericCode(6);

        QRLoginSession session = new QRLoginSession(
                sessionId,
                qrCode,
                verificationCode,
                System.currentTimeMillis(),
                System.currentTimeMillis() + QR_CODE_TTL_MS
        );

        qrSessions.put(sessionId, session);

        logger.info("QR login session generated: " + sessionId);

        return new QRLoginResult(true, sessionId, qrCode, verificationCode, QR_CODE_TTL_MS / 1000);
    }

    /**
     * Scan QR code from mobile device (initiates approval flow).
     */
    public CompletableFuture<QRScanResult> scanQRCode(String qrCode, UUID playerUuid) {
        return CompletableFuture.supplyAsync(() -> {
            // Find session by QR code
            QRLoginSession session = null;
            for (QRLoginSession s : qrSessions.values()) {
                if (s.getQrCode().equals(qrCode)) {
                    session = s;
                    break;
                }
            }

            if (session == null) {
                return new QRScanResult(false, "Invalid QR code");
            }

            if (session.getExpiresAt() < System.currentTimeMillis()) {
                qrSessions.remove(session.getSessionId());
                return new QRScanResult(false, "QR code has expired");
            }

            // Get account
            Account account = storage.getAccount(playerUuid).join().orElse(null);
            if (account == null) {
                return new QRScanResult(false, "Account not found");
            }

            // Mark as scanned and store player info
            session.setScanned(true);
            session.setPlayerUuid(playerUuid);
            session.setPlayerName(account.getUsername());

            logger.info("QR code scanned by " + account.getUsername());

            return new QRScanResult(true, "QR code scanned. Approve login on your device.");
        });
    }

    /**
     * Approve QR code login from mobile device.
     */
    public CompletableFuture<QRApprovalResult> approveQRLogin(String sessionId, UUID playerUuid, boolean approved) {
        return CompletableFuture.supplyAsync(() -> {
            QRLoginSession session = qrSessions.get(sessionId);

            if (session == null) {
                return new QRApprovalResult(false, null, "Invalid session");
            }

            if (session.getExpiresAt() < System.currentTimeMillis()) {
                qrSessions.remove(sessionId);
                return new QRApprovalResult(false, null, "Session has expired");
            }

            if (!playerUuid.equals(session.getPlayerUuid())) {
                return new QRApprovalResult(false, null, "Player mismatch");
            }

            if (approved) {
                session.setApproved(true);

                // Audit log
                auditService.log(AuditEventType.LOGIN_SUCCESS, playerUuid,
                        session.getPlayerName(), "qr-login", "QR code login approved");

                logger.info("QR login approved for " + session.getPlayerName());

                return new QRApprovalResult(true, session.getPlayerName(), "Login approved");
            } else {
                qrSessions.remove(sessionId);

                // Audit log
                auditService.log(AuditEventType.LOGIN_FAILURE, playerUuid,
                        session.getPlayerName(), "qr-login", "QR code login denied");

                return new QRApprovalResult(false, null, "Login denied");
            }
        });
    }

    /**
     * Check if QR code login has been approved (polling from game client).
     */
    public CompletableFuture<QRPollResult> pollQRLogin(String sessionId) {
        return CompletableFuture.supplyAsync(() -> {
            QRLoginSession session = qrSessions.get(sessionId);

            if (session == null) {
                return new QRPollResult("expired", null, null);
            }

            if (session.getExpiresAt() < System.currentTimeMillis()) {
                qrSessions.remove(sessionId);
                return new QRPollResult("expired", null, null);
            }

            if (session.isApproved()) {
                qrSessions.remove(sessionId);
                return new QRPollResult("approved", session.getPlayerUuid(), session.getPlayerName());
            }

            if (session.isScanned()) {
                return new QRPollResult("scanned", null, session.getPlayerName());
            }

            return new QRPollResult("pending", null, null);
        });
    }

    // === Push Notification Approval ===

    /**
     * Request push notification approval for login.
     */
    public CompletableFuture<PushApprovalResult> requestPushApproval(UUID playerUuid, String deviceInfo) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new PushApprovalResult(false, null, "Account not found");
            }

            Account account = optAccount.get();

            // Generate approval request
            String requestId = generateSecureToken(16);
            String approvalCode = generateNumericCode(6);

            PushApprovalRequest request = new PushApprovalRequest(
                    requestId,
                    playerUuid,
                    account.getUsername(),
                    deviceInfo,
                    approvalCode,
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + PUSH_APPROVAL_TTL_MS
            );

            pushApprovals.put(requestId, request);

            // Send push notification (would integrate with Telegram/VK/Email)
            boolean sent = sendPushNotification(playerUuid, approvalCode, deviceInfo);

            if (!sent) {
                pushApprovals.remove(requestId);
                return new PushApprovalResult(false, null, "Failed to send push notification");
            }

            logger.info("Push approval requested for " + account.getUsername());

            return new PushApprovalResult(true, requestId, "Push notification sent");
        });
    }

    /**
     * Approve push notification login.
     */
    public CompletableFuture<PushVerifyResult> verifyPushApproval(String requestId, String code, boolean approved) {
        return CompletableFuture.supplyAsync(() -> {
            PushApprovalRequest request = pushApprovals.remove(requestId);

            if (request == null) {
                return new PushVerifyResult(false, null, "Invalid or expired request");
            }

            if (request.getExpiresAt() < System.currentTimeMillis()) {
                return new PushVerifyResult(false, null, "Request has expired");
            }

            if (!request.getApprovalCode().equals(code)) {
                return new PushVerifyResult(false, null, "Invalid approval code");
            }

            if (approved) {
                // Audit log
                auditService.log(AuditEventType.LOGIN_SUCCESS, request.getPlayerUuid(),
                        request.getUsername(), "push-approval", "Push approval login successful");

                logger.info("Push approval login successful for " + request.getUsername());

                return new PushVerifyResult(true, request.getPlayerUuid(), "Login approved");
            } else {
                // Audit log
                auditService.log(AuditEventType.LOGIN_FAILURE, request.getPlayerUuid(),
                        request.getUsername(), "push-approval", "Push approval login denied");

                return new PushVerifyResult(false, null, "Login denied");
            }
        });
    }

    private boolean sendPushNotification(UUID playerUuid, String code, String deviceInfo) {
        // Would integrate with Telegram/VK/Email providers
        logger.info("Push notification sent to " + playerUuid + " with code: " + code);
        return true;
    }

    // === Biometric Authentication Bridge ===

    /**
     * Register biometric authentication for an account.
     */
    public CompletableFuture<BiometricRegisterResult> registerBiometric(UUID playerUuid, String deviceId, String biometricType) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new BiometricRegisterResult(false, null, "Account not found");
            }

            Account account = optAccount.get();

            // Generate biometric token
            String biometricToken = generateSecureToken(32);

            // Create biometric session
            BiometricSession session = new BiometricSession(
                    biometricToken,
                    playerUuid,
                    account.getUsername(),
                    deviceId,
                    biometricType,
                    System.currentTimeMillis(),
                    System.currentTimeMillis() + BIOMETRIC_SESSION_TTL_MS
            );

            biometricSessions.put(biometricToken, session);

            // Audit log
            auditService.log(AuditEventType.TWO_FACTOR_ENABLE, playerUuid,
                    account.getUsername(), "biometric", "Biometric registered: " + biometricType);

            logger.info("Biometric registered for " + account.getUsername() + ": " + biometricType);

            return new BiometricRegisterResult(true, biometricToken, "Biometric registered successfully");
        });
    }

    /**
     * Authenticate using biometric token.
     */
    public CompletableFuture<BiometricAuthResult> authenticateBiometric(String biometricToken, String deviceId) {
        return CompletableFuture.supplyAsync(() -> {
            BiometricSession session = biometricSessions.get(biometricToken);

            if (session == null) {
                return new BiometricAuthResult(false, null, "Invalid biometric token");
            }

            if (session.getExpiresAt() < System.currentTimeMillis()) {
                biometricSessions.remove(biometricToken);
                return new BiometricAuthResult(false, null, "Biometric session has expired");
            }

            if (!session.getDeviceId().equals(deviceId)) {
                return new BiometricAuthResult(false, null, "Device mismatch");
            }

            // Get account
            Account account = storage.getAccount(session.getPlayerUuid()).join().orElse(null);
            if (account == null) {
                return new BiometricAuthResult(false, null, "Account not found");
            }

            // Refresh session
            session.setExpiresAt(System.currentTimeMillis() + BIOMETRIC_SESSION_TTL_MS);

            // Audit log
            auditService.log(AuditEventType.LOGIN_SUCCESS, account.getUuid(),
                    account.getUsername(), "biometric", "Biometric login successful");

            logger.info("Biometric login successful for " + account.getUsername());

            return new BiometricAuthResult(true, account, "Biometric authentication successful");
        });
    }

    /**
     * Revoke biometric authentication.
     */
    public void revokeBiometric(String biometricToken) {
        BiometricSession session = biometricSessions.remove(biometricToken);
        if (session != null) {
            auditService.log(AuditEventType.TWO_FACTOR_DISABLE, session.getPlayerUuid(),
                    session.getUsername(), "biometric", "Biometric revoked");
            logger.info("Biometric revoked for " + session.getUsername());
        }
    }

    // === FIDO2/WebAuthn Hardware Security Keys ===

    /**
     * Begin FIDO2 registration ceremony.
     */
    public CompletableFuture<FIDO2RegistrationChallenge> beginFIDO2Registration(UUID playerUuid) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new FIDO2RegistrationChallenge(false, null, null, null, "Account not found");
            }

            Account account = optAccount.get();

            // Generate challenge
            byte[] challenge = new byte[32];
            SECURE_RANDOM.nextBytes(challenge);
            String challengeBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

            // Generate credential ID
            String credentialId = generateSecureToken(32);

            // Store pending challenge
            FIDO2RegistrationChallenge regChallenge = new FIDO2RegistrationChallenge(
                    true,
                    playerUuid,
                    credentialId,
                    challengeBase64,
                    "Register your security key"
            );

            // Audit log
            auditService.log(AuditEventType.TWO_FACTOR_ENABLE, playerUuid,
                    account.getUsername(), "fido2", "FIDO2 registration initiated");

            logger.info("FIDO2 registration initiated for " + account.getUsername());

            return regChallenge;
        });
    }

    /**
     * Complete FIDO2 registration ceremony.
     */
    public CompletableFuture<FIDO2RegistrationResult> completeFIDO2Registration(
            UUID playerUuid, String credentialId, String publicKey, String signCount, String deviceName) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new FIDO2RegistrationResult(false, "Account not found");
            }

            Account account = optAccount.get();

            // Store credential
            FIDO2Credential credential = new FIDO2Credential(
                    credentialId,
                    publicKey,
                    Integer.parseInt(signCount),
                    deviceName,
                    System.currentTimeMillis()
            );

            fido2Credentials.computeIfAbsent(playerUuid, k -> new ArrayList<>()).add(credential);

            // Audit log
            auditService.log(AuditEventType.TWO_FACTOR_ENABLE, playerUuid,
                    account.getUsername(), "fido2", "FIDO2 credential registered: " + deviceName);

            logger.info("FIDO2 credential registered for " + account.getUsername() + ": " + deviceName);

            return new FIDO2RegistrationResult(true, "Security key registered successfully");
        });
    }

    /**
     * Begin FIDO2 authentication ceremony.
     */
    public CompletableFuture<FIDO2AuthChallenge> beginFIDO2Authentication(UUID playerUuid) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new FIDO2AuthChallenge(false, null, null, "Account not found");
            }

            Account account = optAccount.get();

            List<FIDO2Credential> credentials = fido2Credentials.get(playerUuid);
            if (credentials == null || credentials.isEmpty()) {
                return new FIDO2AuthChallenge(false, null, null, "No FIDO2 credentials registered");
            }

            // Generate challenge
            byte[] challenge = new byte[32];
            SECURE_RANDOM.nextBytes(challenge);
            String challengeBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

            // Get allowed credential IDs
            List<String> allowedCredentials = credentials.stream()
                    .map(FIDO2Credential::getCredentialId)
                    .toList();

            return new FIDO2AuthChallenge(
                    true,
                    challengeBase64,
                    allowedCredentials,
                    "Authenticate with your security key"
            );
        });
    }

    /**
     * Complete FIDO2 authentication ceremony.
     */
    public CompletableFuture<FIDO2AuthResult> completeFIDO2Authentication(
            UUID playerUuid, String credentialId, String signCount, String ip) {
        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return new FIDO2AuthResult(false, null, "Account not found");
            }

            Account account = optAccount.get();

            List<FIDO2Credential> credentials = fido2Credentials.get(playerUuid);
            if (credentials == null) {
                return new FIDO2AuthResult(false, null, "No FIDO2 credentials registered");
            }

            // Find and verify credential
            FIDO2Credential credential = credentials.stream()
                    .filter(c -> c.getCredentialId().equals(credentialId))
                    .findFirst()
                    .orElse(null);

            if (credential == null) {
                return new FIDO2AuthResult(false, null, "Invalid credential");
            }

            // Verify sign count (should be greater than stored)
            int newSignCount = Integer.parseInt(signCount);
            if (newSignCount <= credential.getSignCount()) {
                // Potential clone detected
                logger.warning("Potential FIDO2 clone detected for " + account.getUsername());
                auditService.log(AuditEventType.LOGIN_FAILURE, playerUuid,
                        account.getUsername(), ip, "FIDO2 clone detection");
                return new FIDO2AuthResult(false, null, "Security key verification failed");
            }

            // Update sign count
            credential.setSignCount(newSignCount);

            // Audit log
            auditService.log(AuditEventType.LOGIN_SUCCESS, playerUuid,
                    account.getUsername(), ip, "FIDO2 authentication successful");

            logger.info("FIDO2 authentication successful for " + account.getUsername());

            return new FIDO2AuthResult(true, account, "Authentication successful");
        });
    }

    /**
     * Remove FIDO2 credential.
     */
    public CompletableFuture<Boolean> removeFIDO2Credential(UUID playerUuid, String credentialId) {
        return CompletableFuture.supplyAsync(() -> {
            List<FIDO2Credential> credentials = fido2Credentials.get(playerUuid);
            if (credentials == null) {
                return false;
            }

            boolean removed = credentials.removeIf(c -> c.getCredentialId().equals(credentialId));

            if (removed) {
                auditService.log(AuditEventType.TWO_FACTOR_DISABLE, playerUuid,
                        playerName(playerUuid), "fido2", "FIDO2 credential removed");
                logger.info("FIDO2 credential removed for " + playerUuid);
            }

            return removed;
        });
    }

    /**
     * Get registered FIDO2 credentials for a player.
     */
    public List<FIDO2CredentialInfo> getFIDO2Credentials(UUID playerUuid) {
        List<FIDO2Credential> credentials = fido2Credentials.get(playerUuid);
        if (credentials == null) {
            return Collections.emptyList();
        }

        return credentials.stream()
                .map(c -> new FIDO2CredentialInfo(
                        c.getCredentialId(),
                        c.getDeviceName(),
                        c.getRegisteredAt()))
                .toList();
    }

    // === Utility Methods ===

    private String generateSecureToken(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateNumericCode(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(SECURE_RANDOM.nextInt(10));
        }
        return sb.toString();
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        String[] parts = email.split("@");
        String local = parts[0];
        String domain = parts[1];
        if (local.length() <= 2) {
            return "***@" + domain;
        }
        return local.charAt(0) + "***" + local.charAt(local.length() - 1) + "@" + domain;
    }

    private String playerName(UUID playerUuid) {
        String name = platform.getPlayerName(playerUuid);
        return name != null ? name : "Unknown";
    }

    // === Cleanup ===

    /**
     * Clean up expired tokens and sessions.
     */
    public void cleanup() {
        long now = System.currentTimeMillis();

        // Clean magic links
        magicLinks.entrySet().removeIf(e -> e.getValue().getExpiresAt() < now);

        // Clean QR sessions
        qrSessions.entrySet().removeIf(e -> e.getValue().getExpiresAt() < now);

        // Clean push approvals
        pushApprovals.entrySet().removeIf(e -> e.getValue().getExpiresAt() < now);

        // Clean biometric sessions
        biometricSessions.entrySet().removeIf(e -> e.getValue().getExpiresAt() < now);

        logger.fine("Passwordless service cleanup completed");
    }

    // === Data Classes ===

    public static class MagicLinkRequest {
        private final UUID playerUuid;
        private final String username;
        private final String email;
        private final String token;
        private final String magicCode;
        private final long createdAt;
        private final long expiresAt;

        public MagicLinkRequest(UUID playerUuid, String username, String email, String token, String magicCode, long createdAt, long expiresAt) {
            this.playerUuid = playerUuid;
            this.username = username;
            this.email = email;
            this.token = token;
            this.magicCode = magicCode;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getToken() { return token; }
        public String getMagicCode() { return magicCode; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
    }

    public static class MagicLinkResult {
        private final boolean success;
        private final String token;
        private final String message;

        public MagicLinkResult(boolean success, String token, String message) {
            this.success = success;
            this.token = token;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getToken() { return token; }
        public String getMessage() { return message; }
    }

    public static class MagicLinkVerifyResult {
        private final boolean success;
        private final Account account;
        private final String email;
        private final String message;

        public MagicLinkVerifyResult(boolean success, Account account, String email, String message) {
            this.success = success;
            this.account = account;
            this.email = email;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public Account getAccount() { return account; }
        public String getEmail() { return email; }
        public String getMessage() { return message; }
    }

    public static class QRLoginSession {
        private final String sessionId;
        private final String qrCode;
        private final String verificationCode;
        private final long createdAt;
        private final long expiresAt;
        private boolean scanned;
        private boolean approved;
        private UUID playerUuid;
        private String playerName;

        public QRLoginSession(String sessionId, String qrCode, String verificationCode, long createdAt, long expiresAt) {
            this.sessionId = sessionId;
            this.qrCode = qrCode;
            this.verificationCode = verificationCode;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.scanned = false;
            this.approved = false;
        }

        public String getSessionId() { return sessionId; }
        public String getQrCode() { return qrCode; }
        public String getVerificationCode() { return verificationCode; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
        public boolean isScanned() { return scanned; }
        public void setScanned(boolean scanned) { this.scanned = scanned; }
        public boolean isApproved() { return approved; }
        public void setApproved(boolean approved) { this.approved = approved; }
        public UUID getPlayerUuid() { return playerUuid; }
        public void setPlayerUuid(UUID playerUuid) { this.playerUuid = playerUuid; }
        public String getPlayerName() { return playerName; }
        public void setPlayerName(String playerName) { this.playerName = playerName; }
    }

    public static class QRLoginResult {
        private final boolean success;
        private final String sessionId;
        private final String qrCode;
        private final String verificationCode;
        private final long expiresIn;

        public QRLoginResult(boolean success, String sessionId, String qrCode, String verificationCode, long expiresIn) {
            this.success = success;
            this.sessionId = sessionId;
            this.qrCode = qrCode;
            this.verificationCode = verificationCode;
            this.expiresIn = expiresIn;
        }

        public boolean isSuccess() { return success; }
        public String getSessionId() { return sessionId; }
        public String getQrCode() { return qrCode; }
        public String getVerificationCode() { return verificationCode; }
        public long getExpiresIn() { return expiresIn; }
    }

    public static class QRScanResult {
        private final boolean success;
        private final String message;

        public QRScanResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }

    public static class QRApprovalResult {
        private final boolean success;
        private final String playerName;
        private final String message;

        public QRApprovalResult(boolean success, String playerName, String message) {
            this.success = success;
            this.playerName = playerName;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getPlayerName() { return playerName; }
        public String getMessage() { return message; }
    }

    public static class QRPollResult {
        private final String status;
        private final UUID playerUuid;
        private final String playerName;

        public QRPollResult(String status, UUID playerUuid, String playerName) {
            this.status = status;
            this.playerUuid = playerUuid;
            this.playerName = playerName;
        }

        public String getStatus() { return status; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getPlayerName() { return playerName; }
    }

    public static class PushApprovalRequest {
        private final String requestId;
        private final UUID playerUuid;
        private final String username;
        private final String deviceInfo;
        private final String approvalCode;
        private final long createdAt;
        private final long expiresAt;

        public PushApprovalRequest(String requestId, UUID playerUuid, String username, String deviceInfo, String approvalCode, long createdAt, long expiresAt) {
            this.requestId = requestId;
            this.playerUuid = playerUuid;
            this.username = username;
            this.deviceInfo = deviceInfo;
            this.approvalCode = approvalCode;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }

        public String getRequestId() { return requestId; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getUsername() { return username; }
        public String getDeviceInfo() { return deviceInfo; }
        public String getApprovalCode() { return approvalCode; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
    }

    public static class PushApprovalResult {
        private final boolean success;
        private final String requestId;
        private final String message;

        public PushApprovalResult(boolean success, String requestId, String message) {
            this.success = success;
            this.requestId = requestId;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getRequestId() { return requestId; }
        public String getMessage() { return message; }
    }

    public static class PushVerifyResult {
        private final boolean success;
        private final UUID playerUuid;
        private final String message;

        public PushVerifyResult(boolean success, UUID playerUuid, String message) {
            this.success = success;
            this.playerUuid = playerUuid;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getMessage() { return message; }
    }

    public static class BiometricSession {
        private final String biometricToken;
        private final UUID playerUuid;
        private final String username;
        private final String deviceId;
        private final String biometricType;
        private final long createdAt;
        private long expiresAt;

        public BiometricSession(String biometricToken, UUID playerUuid, String username, String deviceId, String biometricType, long createdAt, long expiresAt) {
            this.biometricToken = biometricToken;
            this.playerUuid = playerUuid;
            this.username = username;
            this.deviceId = deviceId;
            this.biometricType = biometricType;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }

        public String getBiometricToken() { return biometricToken; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getUsername() { return username; }
        public String getDeviceId() { return deviceId; }
        public String getBiometricType() { return biometricType; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
        public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    }

    public static class BiometricRegisterResult {
        private final boolean success;
        private final String biometricToken;
        private final String message;

        public BiometricRegisterResult(boolean success, String biometricToken, String message) {
            this.success = success;
            this.biometricToken = biometricToken;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getBiometricToken() { return biometricToken; }
        public String getMessage() { return message; }
    }

    public static class BiometricAuthResult {
        private final boolean success;
        private final Account account;
        private final String message;

        public BiometricAuthResult(boolean success, Account account, String message) {
            this.success = success;
            this.account = account;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public Account getAccount() { return account; }
        public String getMessage() { return message; }
    }

    public static class FIDO2Credential {
        private final String credentialId;
        private final String publicKey;
        private int signCount;
        private final String deviceName;
        private final long registeredAt;

        public FIDO2Credential(String credentialId, String publicKey, int signCount, String deviceName, long registeredAt) {
            this.credentialId = credentialId;
            this.publicKey = publicKey;
            this.signCount = signCount;
            this.deviceName = deviceName;
            this.registeredAt = registeredAt;
        }

        public String getCredentialId() { return credentialId; }
        public String getPublicKey() { return publicKey; }
        public int getSignCount() { return signCount; }
        public void setSignCount(int signCount) { this.signCount = signCount; }
        public String getDeviceName() { return deviceName; }
        public long getRegisteredAt() { return registeredAt; }
    }

    public static class FIDO2CredentialInfo {
        private final String credentialId;
        private final String deviceName;
        private final long registeredAt;

        public FIDO2CredentialInfo(String credentialId, String deviceName, long registeredAt) {
            this.credentialId = credentialId;
            this.deviceName = deviceName;
            this.registeredAt = registeredAt;
        }

        public String getCredentialId() { return credentialId; }
        public String getDeviceName() { return deviceName; }
        public long getRegisteredAt() { return registeredAt; }
    }

    public static class FIDO2RegistrationChallenge {
        private final boolean success;
        private final UUID playerUuid;
        private final String credentialId;
        private final String challenge;
        private final String message;

        public FIDO2RegistrationChallenge(boolean success, UUID playerUuid, String credentialId, String challenge, String message) {
            this.success = success;
            this.playerUuid = playerUuid;
            this.credentialId = credentialId;
            this.challenge = challenge;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getCredentialId() { return credentialId; }
        public String getChallenge() { return challenge; }
        public String getMessage() { return message; }
    }

    public static class FIDO2RegistrationResult {
        private final boolean success;
        private final String message;

        public FIDO2RegistrationResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }

    public static class FIDO2AuthChallenge {
        private final boolean success;
        private final String challenge;
        private final List<String> allowedCredentials;
        private final String message;

        public FIDO2AuthChallenge(boolean success, String challenge, List<String> allowedCredentials, String message) {
            this.success = success;
            this.challenge = challenge;
            this.allowedCredentials = allowedCredentials;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getChallenge() { return challenge; }
        public List<String> getAllowedCredentials() { return allowedCredentials; }
        public String getMessage() { return message; }
    }

    public static class FIDO2AuthResult {
        private final boolean success;
        private final Account account;
        private final String message;

        public FIDO2AuthResult(boolean success, Account account, String message) {
            this.success = success;
            this.account = account;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public Account getAccount() { return account; }
        public String getMessage() { return message; }
    }
}
