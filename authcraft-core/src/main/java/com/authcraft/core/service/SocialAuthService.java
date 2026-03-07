// com/authcraft/core/service/SocialAuthService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEventType;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Social Authentication Service.
 *
 * Features:
 * - Discord integration
 * - Google account linking
 * - Microsoft account linking
 * - Custom OAuth2 providers
 * - Account merging
 */
public class SocialAuthService {

    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final StorageProvider storage;
    private final AuditService auditService;
    private final MessageService messageService;
    private final Logger logger;

    // OAuth state tokens (prevent CSRF)
    private final Map<String, OAuthState> oauthStates = new ConcurrentHashMap<>();

    // Linked social accounts (playerUuid -> list of linked accounts)
    private final Map<UUID, List<LinkedSocialAccount>> linkedAccounts = new ConcurrentHashMap<>();

    // Pending account merges
    private final Map<String, AccountMergeRequest> mergeRequests = new ConcurrentHashMap<>();

    // HTTP client for OAuth requests
    private final HttpClient httpClient = HttpClient.newHttpClient();

    // Secure random for state generation
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // OAuth configuration
    private static final String DISCORD_AUTHORIZE_URL = "https://discord.com/api/oauth2/authorize";
    private static final String DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token";
    private static final String DISCORD_API_URL = "https://discord.com/api/v10/users/@me";

    private static final String GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private static final String GOOGLE_API_URL = "https://www.googleapis.com/oauth2/v2/userinfo";

    private static final String MICROSOFT_AUTHORIZE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
    private static final String MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
    private static final String MICROSOFT_API_URL = "https://graph.microsoft.com/v1.0/me";

    // State expiration
    private static final long STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

    /**
     * Creates a new SocialAuthService.
     */
    public SocialAuthService(AuthCraftConfig config, PlatformAdapter platform,
                             StorageProvider storage, AuditService auditService,
                             MessageService messageService) {
        this.config = config;
        this.platform = platform;
        this.storage = storage;
        this.auditService = auditService;
        this.messageService = messageService;
        this.logger = platform.getLogger();
    }

    // === Discord Integration ===

    /**
     * Generate Discord OAuth authorization URL.
     */
    public OAuthUrlResult generateDiscordAuthUrl(UUID playerUuid, String redirectUri) {
        String state = generateSecureToken(32);
        String codeVerifier = generateSecureToken(64);

        OAuthState oauthState = new OAuthState(
                state,
                playerUuid,
                "discord",
                redirectUri,
                codeVerifier,
                System.currentTimeMillis() + STATE_TTL_MS
        );
        oauthStates.put(state, oauthState);

        String authUrl = String.format("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=identify&state=%s",
                DISCORD_AUTHORIZE_URL,
                config.getDiscordClientId(),
                encodeUrl(redirectUri),
                state);

        logger.info("Discord OAuth URL generated for " + playerUuid);
        return new OAuthUrlResult(true, authUrl, state);
    }

    /**
     * Handle Discord OAuth callback.
     */
    public CompletableFuture<OAuthCallbackResult> handleDiscordCallback(String code, String state) {
        OAuthState oauthState = oauthStates.remove(state);
        if (oauthState == null || oauthState.getExpiresAt() < System.currentTimeMillis()) {
            return CompletableFuture.completedFuture(
                    new OAuthCallbackResult(false, null, "Invalid or expired state"));
        }

        return exchangeDiscordCode(code, oauthState)
                .thenCompose(tokenResponse -> getDiscordUserInfo(tokenResponse.getAccessToken()))
                .thenApply(userInfo -> {
                    // Create linked account
                    LinkedSocialAccount linked = new LinkedSocialAccount(
                            oauthState.getPlayerUuid(),
                            "discord",
                            userInfo.getId(),
                            userInfo.getUsername(),
                            userInfo.getAvatarUrl(),
                            System.currentTimeMillis()
                    );

                    // Store linked account
                    linkedAccounts.computeIfAbsent(oauthState.getPlayerUuid(), k -> new ArrayList<>())
                            .add(linked);

                    // Audit log
                    auditService.log(AuditEventType.TWO_FACTOR_ENABLE, oauthState.getPlayerUuid(),
                            playerName(oauthState.getPlayerUuid()), "discord",
                            "Discord account linked: " + userInfo.getUsername());

                    logger.info("Discord account linked for " + oauthState.getPlayerUuid() + ": " + userInfo.getUsername());

                    return new OAuthCallbackResult(true, userInfo, "Discord account linked successfully");
                });
    }

    private CompletableFuture<DiscordTokenResponse> exchangeDiscordCode(String code, OAuthState state) {
        String body = String.format("client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=%s",
                config.getDiscordClientId(),
                config.getDiscordClientSecret(),
                code,
                encodeUrl(state.getRedirectUri()));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(DISCORD_TOKEN_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != 200) {
                        throw new RuntimeException("Discord token exchange failed: " + response.body());
                    }
                    return parseDiscordTokenResponse(response.body());
                });
    }

    private CompletableFuture<DiscordUserInfo> getDiscordUserInfo(String accessToken) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(DISCORD_API_URL))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != 200) {
                        throw new RuntimeException("Discord user info failed: " + response.body());
                    }
                    return parseDiscordUserInfo(response.body());
                });
    }

    // === Google Integration ===

    /**
     * Generate Google OAuth authorization URL.
     */
    public OAuthUrlResult generateGoogleAuthUrl(UUID playerUuid, String redirectUri) {
        String state = generateSecureToken(32);

        OAuthState oauthState = new OAuthState(
                state,
                playerUuid,
                "google",
                redirectUri,
                null,
                System.currentTimeMillis() + STATE_TTL_MS
        );
        oauthStates.put(state, oauthState);

        String authUrl = String.format("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=email profile&state=%s",
                GOOGLE_AUTHORIZE_URL,
                config.getGoogleClientId(),
                encodeUrl(redirectUri),
                state);

        logger.info("Google OAuth URL generated for " + playerUuid);
        return new OAuthUrlResult(true, authUrl, state);
    }

    /**
     * Handle Google OAuth callback.
     */
    public CompletableFuture<OAuthCallbackResult> handleGoogleCallback(String code, String state) {
        OAuthState oauthState = oauthStates.remove(state);
        if (oauthState == null || oauthState.getExpiresAt() < System.currentTimeMillis()) {
            return CompletableFuture.completedFuture(
                    new OAuthCallbackResult(false, null, "Invalid or expired state"));
        }

        return exchangeGoogleCode(code, oauthState)
                .thenCompose(tokenResponse -> getGoogleUserInfo(tokenResponse.getAccessToken()))
                .thenApply(userInfo -> {
                    // Create linked account
                    LinkedSocialAccount linked = new LinkedSocialAccount(
                            oauthState.getPlayerUuid(),
                            "google",
                            userInfo.getId(),
                            userInfo.getName(),
                            userInfo.getPicture(),
                            System.currentTimeMillis()
                    );

                    // Store linked account
                    linkedAccounts.computeIfAbsent(oauthState.getPlayerUuid(), k -> new ArrayList<>())
                            .add(linked);

                    // Audit log
                    auditService.log(AuditEventType.TWO_FACTOR_ENABLE, oauthState.getPlayerUuid(),
                            playerName(oauthState.getPlayerUuid()), "google",
                            "Google account linked: " + userInfo.getEmail());

                    logger.info("Google account linked for " + oauthState.getPlayerUuid() + ": " + userInfo.getName());

                    return new OAuthCallbackResult(true, userInfo, "Google account linked successfully");
                });
    }

    private CompletableFuture<GoogleTokenResponse> exchangeGoogleCode(String code, OAuthState state) {
        String body = String.format("client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=%s",
                config.getGoogleClientId(),
                config.getGoogleClientSecret(),
                code,
                encodeUrl(state.getRedirectUri()));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(GOOGLE_TOKEN_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != 200) {
                        throw new RuntimeException("Google token exchange failed: " + response.body());
                    }
                    return parseGoogleTokenResponse(response.body());
                });
    }

    private CompletableFuture<GoogleUserInfo> getGoogleUserInfo(String accessToken) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(GOOGLE_API_URL))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != 200) {
                        throw new RuntimeException("Google user info failed: " + response.body());
                    }
                    return parseGoogleUserInfo(response.body());
                });
    }

    // === Microsoft Integration ===

    /**
     * Generate Microsoft OAuth authorization URL.
     */
    public OAuthUrlResult generateMicrosoftAuthUrl(UUID playerUuid, String redirectUri) {
        String state = generateSecureToken(32);

        OAuthState oauthState = new OAuthState(
                state,
                playerUuid,
                "microsoft",
                redirectUri,
                null,
                System.currentTimeMillis() + STATE_TTL_MS
        );
        oauthStates.put(state, oauthState);

        String authUrl = String.format("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=User.Read&state=%s",
                MICROSOFT_AUTHORIZE_URL,
                config.getMicrosoftClientId(),
                encodeUrl(redirectUri),
                state);

        logger.info("Microsoft OAuth URL generated for " + playerUuid);
        return new OAuthUrlResult(true, authUrl, state);
    }

    /**
     * Handle Microsoft OAuth callback.
     */
    public CompletableFuture<OAuthCallbackResult> handleMicrosoftCallback(String code, String state) {
        OAuthState oauthState = oauthStates.remove(state);
        if (oauthState == null || oauthState.getExpiresAt() < System.currentTimeMillis()) {
            return CompletableFuture.completedFuture(
                    new OAuthCallbackResult(false, null, "Invalid or expired state"));
        }

        return exchangeMicrosoftCode(code, oauthState)
                .thenCompose(tokenResponse -> getMicrosoftUserInfo(tokenResponse.getAccessToken()))
                .thenApply(userInfo -> {
                    // Create linked account
                    LinkedSocialAccount linked = new LinkedSocialAccount(
                            oauthState.getPlayerUuid(),
                            "microsoft",
                            userInfo.getId(),
                            userInfo.getDisplayName(),
                            null,
                            System.currentTimeMillis()
                    );

                    // Store linked account
                    linkedAccounts.computeIfAbsent(oauthState.getPlayerUuid(), k -> new ArrayList<>())
                            .add(linked);

                    // Audit log
                    auditService.log(AuditEventType.TWO_FACTOR_ENABLE, oauthState.getPlayerUuid(),
                            playerName(oauthState.getPlayerUuid()), "microsoft",
                            "Microsoft account linked: " + userInfo.getDisplayName());

                    logger.info("Microsoft account linked for " + oauthState.getPlayerUuid() + ": " + userInfo.getDisplayName());

                    return new OAuthCallbackResult(true, userInfo, "Microsoft account linked successfully");
                });
    }

    private CompletableFuture<MicrosoftTokenResponse> exchangeMicrosoftCode(String code, OAuthState state) {
        String body = String.format("client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=%s",
                config.getMicrosoftClientId(),
                config.getMicrosoftClientSecret(),
                code,
                encodeUrl(state.getRedirectUri()));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(MICROSOFT_TOKEN_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != 200) {
                        throw new RuntimeException("Microsoft token exchange failed: " + response.body());
                    }
                    return parseMicrosoftTokenResponse(response.body());
                });
    }

    private CompletableFuture<MicrosoftUserInfo> getMicrosoftUserInfo(String accessToken) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(MICROSOFT_API_URL))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != 200) {
                        throw new RuntimeException("Microsoft user info failed: " + response.body());
                    }
                    return parseMicrosoftUserInfo(response.body());
                });
    }

    // === Custom OAuth2 Provider ===

    /**
     * Generate custom OAuth2 authorization URL.
     */
    public OAuthUrlResult generateCustomOAuthUrl(UUID playerUuid, String providerName,
                                                  String authorizeUrl, String clientId,
                                                  String scope, String redirectUri) {
        String state = generateSecureToken(32);

        OAuthState oauthState = new OAuthState(
                state,
                playerUuid,
                providerName,
                redirectUri,
                null,
                System.currentTimeMillis() + STATE_TTL_MS
        );
        oauthStates.put(state, oauthState);

        String authUrl = String.format("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
                authorizeUrl,
                clientId,
                encodeUrl(redirectUri),
                encodeUrl(scope),
                state);

        logger.info("Custom OAuth URL generated for " + playerUuid + " (" + providerName + ")");
        return new OAuthUrlResult(true, authUrl, state);
    }

    // === Account Merging ===

    /**
     * Request account merge between two accounts.
     */
    public CompletableFuture<AccountMergeResult> requestAccountMerge(UUID primaryUuid, UUID secondaryUuid) {
        return storage.getAccount(primaryUuid).thenCompose(primaryOpt -> {
            if (primaryOpt.isEmpty()) {
                return CompletableFuture.completedFuture(
                    new AccountMergeResult(false, null, "Primary account not found"));
            }
    
            return storage.getAccount(secondaryUuid).thenApply(secondaryOpt -> {
                if (secondaryOpt.isEmpty()) {
                    return new AccountMergeResult(false, null, "Secondary account not found");
                }

                // Generate merge token
                String mergeToken = generateSecureToken(32);

                AccountMergeRequest request = new AccountMergeRequest(
                        mergeToken,
                        primaryUuid,
                        secondaryUuid,
                        primaryOpt.get().getUsername(),
                        secondaryOpt.get().getUsername(),
                        System.currentTimeMillis(),
                        System.currentTimeMillis() + STATE_TTL_MS
                );

                mergeRequests.put(mergeToken, request);

                // Audit log
                auditService.log(AuditEventType.TWO_FACTOR_ENABLE, primaryUuid,
                        primaryOpt.get().getUsername(), "account-merge",
                        "Account merge requested with: " + secondaryOpt.get().getUsername());

                logger.info("Account merge requested: " + primaryUuid + " <- " + secondaryUuid);

                return new AccountMergeResult(true, mergeToken, "Merge request created. Confirm to proceed.");
            });
        });
    }

    /**
     * Confirm and execute account merge.
     */
    public CompletableFuture<AccountMergeResult> confirmAccountMerge(String mergeToken) {
        AccountMergeRequest request = mergeRequests.remove(mergeToken);
        if (request == null || request.getExpiresAt() < System.currentTimeMillis()) {
            return CompletableFuture.completedFuture(
                new AccountMergeResult(false, null, "Invalid or expired merge token"));
        }
    
        return storage.getAccount(request.getPrimaryUuid()).thenCompose(primaryOpt -> {
            if (primaryOpt.isEmpty()) {
                return CompletableFuture.completedFuture(
                    new AccountMergeResult(false, null, "Primary account not found"));
            }
    
            return storage.getAccount(request.getSecondaryUuid()).thenCompose(secondaryOpt -> {
                if (secondaryOpt.isEmpty()) {
                    return CompletableFuture.completedFuture(
                        new AccountMergeResult(false, null, "Secondary account not found"));
                }

                Account primary = primaryOpt.get();
                Account secondary = secondaryOpt.get();

                // Merge linked accounts
                List<LinkedSocialAccount> secondaryLinks = linkedAccounts.remove(request.getSecondaryUuid());
                if (secondaryLinks != null) {
                    linkedAccounts.computeIfAbsent(request.getPrimaryUuid(), k -> new ArrayList<>())
                            .addAll(secondaryLinks);
                }

                // Merge 2FA methods (keep primary's methods, add secondary's if not present)
                Set<com.authcraft.core.model.TwoFactorMethod> primaryMethods = primary.getEnabledTwoFactorMethods();
                Set<com.authcraft.core.model.TwoFactorMethod> secondaryMethods = secondary.getEnabledTwoFactorMethods();
                for (com.authcraft.core.model.TwoFactorMethod method : secondaryMethods) {
                    if (!primaryMethods.contains(method)) {
                        primary.enableTwoFactorMethod(method);
                    }
                }

                // Delete secondary account
                return storage.deleteAccount(request.getSecondaryUuid()).thenApply(v -> {
                    // Audit log
                    auditService.log(AuditEventType.TWO_FACTOR_ENABLE, request.getPrimaryUuid(),
                            primary.getUsername(), "account-merge",
                            "Account merge completed: merged " + request.getSecondaryUsername());

                    logger.info("Account merge completed: " + request.getPrimaryUuid() + " <- " + request.getSecondaryUuid());

                    return new AccountMergeResult(true, null, "Accounts merged successfully");
                });
            });
        });
    }

    // === Linked Account Management ===

    /**
     * Get all linked social accounts for a player.
     */
    public List<LinkedSocialAccount> getLinkedAccounts(UUID playerUuid) {
        return linkedAccounts.getOrDefault(playerUuid, Collections.emptyList());
    }

    /**
     * Unlink a social account.
     */
    public CompletableFuture<Boolean> unlinkAccount(UUID playerUuid, String provider, String providerId) {
        List<LinkedSocialAccount> accounts = linkedAccounts.get(playerUuid);
        if (accounts == null) {
            return CompletableFuture.completedFuture(false);
        }

        boolean removed = accounts.removeIf(a ->
                a.getProvider().equals(provider) && a.getProviderId().equals(providerId));

        if (removed) {
            auditService.log(AuditEventType.TWO_FACTOR_DISABLE, playerUuid,
                    playerName(playerUuid), provider, "Social account unlinked");
            logger.info("Social account unlinked: " + playerUuid + " (" + provider + ")");
        }

        return CompletableFuture.completedFuture(removed);
    }

    /**
     * Check if a player has a specific social account linked.
     */
    public boolean hasLinkedAccount(UUID playerUuid, String provider) {
        List<LinkedSocialAccount> accounts = linkedAccounts.get(playerUuid);
        if (accounts == null) return false;
        return accounts.stream().anyMatch(a -> a.getProvider().equals(provider));
    }

    /**
     * Find player by linked social account.
     */
    public Optional<UUID> findPlayerBySocialAccount(String provider, String providerId) {
        for (Map.Entry<UUID, List<LinkedSocialAccount>> entry : linkedAccounts.entrySet()) {
            for (LinkedSocialAccount account : entry.getValue()) {
                if (account.getProvider().equals(provider) && account.getProviderId().equals(providerId)) {
                    return Optional.of(entry.getKey());
                }
            }
        }
        return Optional.empty();
    }

    // === Utility Methods ===

    private String generateSecureToken(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String encodeUrl(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private String playerName(UUID playerUuid) {
        String name = platform.getPlayerName(playerUuid);
        return name != null ? name : "Unknown";
    }

    // JSON parsing helpers (simple implementation)
    private DiscordTokenResponse parseDiscordTokenResponse(String json) {
        String accessToken = extractJsonString(json, "access_token");
        String refreshToken = extractJsonString(json, "refresh_token");
        int expiresIn = extractJsonInt(json, "expires_in");
        return new DiscordTokenResponse(accessToken, refreshToken, expiresIn);
    }

    private DiscordUserInfo parseDiscordUserInfo(String json) {
        String id = extractJsonString(json, "id");
        String username = extractJsonString(json, "username");
        String avatar = extractJsonString(json, "avatar");
        String avatarUrl = avatar != null ?
                "https://cdn.discordapp.com/avatars/" + id + "/" + avatar + ".png" : null;
        return new DiscordUserInfo(id, username, avatarUrl);
    }

    private GoogleTokenResponse parseGoogleTokenResponse(String json) {
        String accessToken = extractJsonString(json, "access_token");
        String refreshToken = extractJsonString(json, "refresh_token");
        int expiresIn = extractJsonInt(json, "expires_in");
        return new GoogleTokenResponse(accessToken, refreshToken, expiresIn);
    }

    private GoogleUserInfo parseGoogleUserInfo(String json) {
        String id = extractJsonString(json, "id");
        String name = extractJsonString(json, "name");
        String email = extractJsonString(json, "email");
        String picture = extractJsonString(json, "picture");
        return new GoogleUserInfo(id, name, email, picture);
    }

    private MicrosoftTokenResponse parseMicrosoftTokenResponse(String json) {
        String accessToken = extractJsonString(json, "access_token");
        String refreshToken = extractJsonString(json, "refresh_token");
        int expiresIn = extractJsonInt(json, "expires_in");
        return new MicrosoftTokenResponse(accessToken, refreshToken, expiresIn);
    }

    private MicrosoftUserInfo parseMicrosoftUserInfo(String json) {
        String id = extractJsonString(json, "id");
        String displayName = extractJsonString(json, "displayName");
        return new MicrosoftUserInfo(id, displayName);
    }

    private String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"";
        int start = json.indexOf(pattern);
        if (start == -1) return null;
        start = json.indexOf("\"", start + pattern.length() - 1) + 1;
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }

    private int extractJsonInt(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*";
        int start = json.indexOf(pattern);
        if (start == -1) return 0;
        start = start + pattern.length();
        while (start < json.length() && !Character.isDigit(json.charAt(start))) start++;
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
        return Integer.parseInt(json.substring(start, end));
    }

    // === Cleanup ===

    /**
     * Clean up expired OAuth states and merge requests.
     */
    public void cleanup() {
        long now = System.currentTimeMillis();

        oauthStates.entrySet().removeIf(e -> e.getValue().getExpiresAt() < now);
        mergeRequests.entrySet().removeIf(e -> e.getValue().getExpiresAt() < now);

        logger.fine("Social auth service cleanup completed");
    }

    // === Data Classes ===

    public static class OAuthState {
        private final String state;
        private final UUID playerUuid;
        private final String provider;
        private final String redirectUri;
        private final String codeVerifier;
        private final long expiresAt;

        public OAuthState(String state, UUID playerUuid, String provider, String redirectUri, String codeVerifier, long expiresAt) {
            this.state = state;
            this.playerUuid = playerUuid;
            this.provider = provider;
            this.redirectUri = redirectUri;
            this.codeVerifier = codeVerifier;
            this.expiresAt = expiresAt;
        }

        public String getState() { return state; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getProvider() { return provider; }
        public String getRedirectUri() { return redirectUri; }
        public String getCodeVerifier() { return codeVerifier; }
        public long getExpiresAt() { return expiresAt; }
    }

    public static class OAuthUrlResult {
        private final boolean success;
        private final String authUrl;
        private final String state;

        public OAuthUrlResult(boolean success, String authUrl, String state) {
            this.success = success;
            this.authUrl = authUrl;
            this.state = state;
        }

        public boolean isSuccess() { return success; }
        public String getAuthUrl() { return authUrl; }
        public String getState() { return state; }
    }

    public static class OAuthCallbackResult {
        private final boolean success;
        private final Object userInfo;
        private final String message;

        public OAuthCallbackResult(boolean success, Object userInfo, String message) {
            this.success = success;
            this.userInfo = userInfo;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public Object getUserInfo() { return userInfo; }
        public String getMessage() { return message; }
    }

    public static class LinkedSocialAccount {
        private final UUID playerUuid;
        private final String provider;
        private final String providerId;
        private final String providerUsername;
        private final String avatarUrl;
        private final long linkedAt;

        public LinkedSocialAccount(UUID playerUuid, String provider, String providerId, String providerUsername, String avatarUrl, long linkedAt) {
            this.playerUuid = playerUuid;
            this.provider = provider;
            this.providerId = providerId;
            this.providerUsername = providerUsername;
            this.avatarUrl = avatarUrl;
            this.linkedAt = linkedAt;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getProvider() { return provider; }
        public String getProviderId() { return providerId; }
        public String getProviderUsername() { return providerUsername; }
        public String getAvatarUrl() { return avatarUrl; }
        public long getLinkedAt() { return linkedAt; }
    }

    public static class AccountMergeRequest {
        private final String mergeToken;
        private final UUID primaryUuid;
        private final UUID secondaryUuid;
        private final String primaryUsername;
        private final String secondaryUsername;
        private final long createdAt;
        private final long expiresAt;

        public AccountMergeRequest(String mergeToken, UUID primaryUuid, UUID secondaryUuid, String primaryUsername, String secondaryUsername, long createdAt, long expiresAt) {
            this.mergeToken = mergeToken;
            this.primaryUuid = primaryUuid;
            this.secondaryUuid = secondaryUuid;
            this.primaryUsername = primaryUsername;
            this.secondaryUsername = secondaryUsername;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }

        public String getMergeToken() { return mergeToken; }
        public UUID getPrimaryUuid() { return primaryUuid; }
        public UUID getSecondaryUuid() { return secondaryUuid; }
        public String getPrimaryUsername() { return primaryUsername; }
        public String getSecondaryUsername() { return secondaryUsername; }
        public long getCreatedAt() { return createdAt; }
        public long getExpiresAt() { return expiresAt; }
    }

    public static class AccountMergeResult {
        private final boolean success;
        private final String mergeToken;
        private final String message;

        public AccountMergeResult(boolean success, String mergeToken, String message) {
            this.success = success;
            this.mergeToken = mergeToken;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getMergeToken() { return mergeToken; }
        public String getMessage() { return message; }
    }

    public static class DiscordTokenResponse {
        private final String accessToken;
        private final String refreshToken;
        private final int expiresIn;

        public DiscordTokenResponse(String accessToken, String refreshToken, int expiresIn) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expiresIn = expiresIn;
        }

        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
        public int getExpiresIn() { return expiresIn; }
    }

    public static class DiscordUserInfo {
        private final String id;
        private final String username;
        private final String avatarUrl;

        public DiscordUserInfo(String id, String username, String avatarUrl) {
            this.id = id;
            this.username = username;
            this.avatarUrl = avatarUrl;
        }

        public String getId() { return id; }
        public String getUsername() { return username; }
        public String getAvatarUrl() { return avatarUrl; }
    }

    public static class GoogleTokenResponse {
        private final String accessToken;
        private final String refreshToken;
        private final int expiresIn;

        public GoogleTokenResponse(String accessToken, String refreshToken, int expiresIn) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expiresIn = expiresIn;
        }

        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
        public int getExpiresIn() { return expiresIn; }
    }

    public static class GoogleUserInfo {
        private final String id;
        private final String name;
        private final String email;
        private final String picture;

        public GoogleUserInfo(String id, String name, String email, String picture) {
            this.id = id;
            this.name = name;
            this.email = email;
            this.picture = picture;
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getEmail() { return email; }
        public String getPicture() { return picture; }
    }

    public static class MicrosoftTokenResponse {
        private final String accessToken;
        private final String refreshToken;
        private final int expiresIn;

        public MicrosoftTokenResponse(String accessToken, String refreshToken, int expiresIn) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expiresIn = expiresIn;
        }

        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
        public int getExpiresIn() { return expiresIn; }
    }

    public static class MicrosoftUserInfo {
        private final String id;
        private final String displayName;

        public MicrosoftUserInfo(String id, String displayName) {
            this.id = id;
            this.displayName = displayName;
        }

        public String getId() { return id; }
        public String getDisplayName() { return displayName; }
    }
}
