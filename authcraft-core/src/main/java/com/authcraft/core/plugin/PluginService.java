// com/authcraft/core/plugin/PluginService.java
package com.authcraft.core.plugin;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.service.AuditService;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Plugin ecosystem service for third-party integrations.
 * Provides public API, webhooks, custom authentication providers, and event system.
 */
public class PluginService {

    private final AuthCraftConfig config;
    private final StorageProvider storage;
    private final PlatformAdapter platform;
    private final AuditService auditService;
    private final Logger logger;

    // Registered plugins
    private final Map<String, RegisteredPlugin> registeredPlugins = new ConcurrentHashMap<>();

    // Event listeners
    private final Map<AuthCraftEvent.EventType, List<EventListener<?>>> eventListeners = new ConcurrentHashMap<>();

    // Webhook endpoints
    private final Map<String, WebhookEndpoint> webhooks = new ConcurrentHashMap<>();
    private final List<WebhookDelivery> webhookHistory = Collections.synchronizedList(new ArrayList<>());

    // Custom authentication providers
    private final Map<String, CustomAuthProvider> authProviders = new ConcurrentHashMap<>();
    private final Map<String, AuthProviderPriority> authProviderPriorities = new ConcurrentHashMap<>();

    // API keys
    private final Map<String, ApiKey> apiKeys = new ConcurrentHashMap<>();

    // Plugin marketplace cache
    private final Map<String, MarketplacePlugin> marketplaceCache = new ConcurrentHashMap<>();
    private long lastMarketplaceUpdate = 0;

    private static final int MAX_WEBHOOK_HISTORY = 1000;
    private static final long MARKETPLACE_CACHE_TTL = 3600000; // 1 hour

    public PluginService(AuthCraftConfig config, StorageProvider storage,
                         PlatformAdapter platform, AuditService auditService) {
        this.config = config;
        this.storage = storage;
        this.platform = platform;
        this.auditService = auditService;
        this.logger = Logger.getLogger("AuthCraft-Plugins");

        initializeEventTypes();
    }

    // === Initialization ===

    private void initializeEventTypes() {
        for (AuthCraftEvent.EventType type : AuthCraftEvent.EventType.values()) {
            eventListeners.put(type, new CopyOnWriteArrayList<>());
        }
    }

    // === Plugin Registration ===

    /**
     * Register a third-party plugin with AuthCraft.
     */
    public PluginRegistrationResult registerPlugin(PluginDescriptor descriptor) {
        // Validate descriptor
        if (descriptor.getName() == null || descriptor.getName().isEmpty()) {
            return new PluginRegistrationResult(false, null, "Plugin name is required");
        }
        if (descriptor.getVersion() == null || descriptor.getVersion().isEmpty()) {
            return new PluginRegistrationResult(false, null, "Plugin version is required");
        }
        if (descriptor.getMainClass() == null) {
            return new PluginRegistrationResult(false, null, "Main class is required");
        }

        // Check for duplicate
        if (registeredPlugins.containsKey(descriptor.getName())) {
            return new PluginRegistrationResult(false, null, "Plugin already registered: " + descriptor.getName());
        }

        // Generate plugin ID and API key
        String pluginId = generatePluginId(descriptor.getName());
        String apiKey = generateApiKey();

        // Create registered plugin
        RegisteredPlugin plugin = new RegisteredPlugin(
            pluginId,
            descriptor.getName(),
            descriptor.getVersion(),
            descriptor.getDescription(),
            descriptor.getAuthor(),
            descriptor.getMainClass(),
            descriptor.getDependencies(),
            System.currentTimeMillis(),
            apiKey
        );

        registeredPlugins.put(pluginId, plugin);

        // Store API key
        apiKeys.put(apiKey, new ApiKey(
            apiKey,
            pluginId,
            descriptor.getName(),
            System.currentTimeMillis(),
            true
        ));

        // Audit log
        auditService.log(AuditEventType.CUSTOM, null, "system", "plugin-register",
            "Plugin registered: " + descriptor.getName() + " v" + descriptor.getVersion());

        logger.info("Plugin registered: " + descriptor.getName() + " (ID: " + pluginId + ")");

        return new PluginRegistrationResult(true, pluginId, "Plugin registered successfully", apiKey);
    }

    /**
     * Unregister a plugin.
     */
    public boolean unregisterPlugin(String pluginId) {
        RegisteredPlugin plugin = registeredPlugins.remove(pluginId);
        if (plugin == null) {
            return false;
        }

        // Remove API key
        apiKeys.remove(plugin.getApiKey());

        // Remove all event listeners for this plugin
        for (List<EventListener<?>> listeners : eventListeners.values()) {
            listeners.removeIf(l -> l.getPluginId().equals(pluginId));
        }

        // Remove webhooks for this plugin
        webhooks.entrySet().removeIf(e -> e.getValue().getPluginId().equals(pluginId));

        // Remove auth providers for this plugin
        authProviders.entrySet().removeIf(e -> e.getValue().getPluginId().equals(pluginId));

        auditService.log(AuditEventType.CUSTOM, null, "system", "plugin-unregister",
            "Plugin unregistered: " + plugin.getName());

        logger.info("Plugin unregistered: " + plugin.getName());
        return true;
    }

    /**
     * Get all registered plugins.
     */
    public List<RegisteredPlugin> getRegisteredPlugins() {
        return new ArrayList<>(registeredPlugins.values());
    }

    /**
     * Get a specific plugin by ID.
     */
    public Optional<RegisteredPlugin> getPlugin(String pluginId) {
        return Optional.ofNullable(registeredPlugins.get(pluginId));
    }

    private String generatePluginId(String name) {
        return name.toLowerCase().replaceAll("[^a-z0-9]", "-") + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private String generateApiKey() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // === Event System ===

    /**
     * Subscribe to an event type.
     */
    public <T> void subscribe(String pluginId, AuthCraftEvent.EventType eventType,
                              Class<T> eventClass, Consumer<AuthCraftEvent<T>> handler) {
        EventListener<T> listener = new EventListener<>(pluginId, eventType, eventClass, handler);
        eventListeners.get(eventType).add(listener);

        logger.fine("Plugin " + pluginId + " subscribed to event: " + eventType);
    }

    /**
     * Unsubscribe from an event type.
     */
    public void unsubscribe(String pluginId, AuthCraftEvent.EventType eventType) {
        eventListeners.get(eventType).removeIf(l -> l.getPluginId().equals(pluginId));
    }

    /**
     * Emit an event to all subscribers.
     */
    @SuppressWarnings("unchecked")
    public <T> void emitEvent(AuthCraftEvent.EventType eventType, T data) {
        AuthCraftEvent<T> event = new AuthCraftEvent<>(eventType, data, System.currentTimeMillis());

        List<EventListener<?>> listeners = eventListeners.get(eventType);
        if (listeners == null) return;

        for (EventListener<?> listener : listeners) {
            try {
                ((EventListener<T>) listener).getHandler().accept(event);
            } catch (Exception e) {
                logger.warning("Error in event handler for " + eventType + " in plugin " + listener.getPluginId() +
                              ": " + e.getMessage());
            }
        }

        // Also trigger webhooks for this event
        triggerWebhooks(eventType, event);
    }

    /**
     * Emit an event asynchronously.
     */
    public <T> void emitEventAsync(AuthCraftEvent.EventType eventType, T data) {
        CompletableFuture.runAsync(() -> emitEvent(eventType, data));
    }

    // === Webhook System ===

    /**
     * Register a webhook endpoint.
     */
    public WebhookRegistrationResult registerWebhook(String pluginId, WebhookConfig config) {
        // Validate
        if (config.getUrl() == null || config.getUrl().isEmpty()) {
            return new WebhookRegistrationResult(false, null, "Webhook URL is required");
        }
        if (config.getEvents() == null || config.getEvents().isEmpty()) {
            return new WebhookRegistrationResult(false, null, "At least one event type is required");
        }

        // Validate plugin exists
        if (!registeredPlugins.containsKey(pluginId)) {
            return new WebhookRegistrationResult(false, null, "Plugin not registered: " + pluginId);
        }

        // Generate webhook ID
        String webhookId = "wh-" + UUID.randomUUID().toString().substring(0, 8);

        // Create webhook
        WebhookEndpoint webhook = new WebhookEndpoint(
            webhookId,
            pluginId,
            config.getUrl(),
            config.getSecret(),
            config.getEvents(),
            config.getHeaders(),
            true,
            System.currentTimeMillis()
        );

        webhooks.put(webhookId, webhook);

        logger.info("Webhook registered: " + webhookId + " for plugin " + pluginId);

        return new WebhookRegistrationResult(true, webhookId, "Webhook registered successfully");
    }

    /**
     * Unregister a webhook.
     */
    public boolean unregisterWebhook(String webhookId) {
        WebhookEndpoint webhook = webhooks.remove(webhookId);
        if (webhook == null) {
            return false;
        }

        logger.info("Webhook unregistered: " + webhookId);
        return true;
    }

    /**
     * Get all webhooks for a plugin.
     */
    public List<WebhookEndpoint> getPluginWebhooks(String pluginId) {
        return webhooks.values().stream()
            .filter(w -> w.getPluginId().equals(pluginId))
            .toList();
    }

    /**
     * Trigger webhooks for an event.
     */
    private void triggerWebhooks(AuthCraftEvent.EventType eventType, AuthCraftEvent<?> event) {
        for (WebhookEndpoint webhook : webhooks.values()) {
            if (!webhook.isEnabled()) continue;
            if (!webhook.getEvents().contains(eventType)) continue;

            // Deliver webhook asynchronously
            CompletableFuture.runAsync(() -> deliverWebhook(webhook, event));
        }
    }

    /**
     * Deliver a webhook.
     */
    private void deliverWebhook(WebhookEndpoint webhook, AuthCraftEvent<?> event) {
        long startTime = System.currentTimeMillis();
        boolean success = false;
        int responseCode = 0;
        String errorMessage = null;

        try {
            // Build payload
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("event", event.getType().name());
            payload.put("timestamp", event.getTimestamp());
            payload.put("data", event.getData());

            String jsonPayload = toJson(payload);

            // Send HTTP POST request
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                new java.net.URL(webhook.getUrl()).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-AuthCraft-Event", event.getType().name());
            conn.setRequestProperty("X-AuthCraft-Timestamp", String.valueOf(event.getTimestamp()));

            // Add signature if secret is configured
            if (webhook.getSecret() != null && !webhook.getSecret().isEmpty()) {
                String signature = calculateSignature(jsonPayload, webhook.getSecret());
                conn.setRequestProperty("X-AuthCraft-Signature", signature);
            }

            // Add custom headers
            if (webhook.getHeaders() != null) {
                for (Map.Entry<String, String> header : webhook.getHeaders().entrySet()) {
                    conn.setRequestProperty(header.getKey(), header.getValue());
                }
            }

            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(30000);

            // Send payload
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(jsonPayload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }

            responseCode = conn.getResponseCode();
            success = responseCode >= 200 && responseCode < 300;

            if (!success) {
                errorMessage = "HTTP " + responseCode;
            }

        } catch (Exception e) {
            errorMessage = e.getMessage();
        }

        // Record delivery
        WebhookDelivery delivery = new WebhookDelivery(
            UUID.randomUUID().toString(),
            webhook.getId(),
            event.getType(),
            System.currentTimeMillis(),
            System.currentTimeMillis() - startTime,
            success,
            responseCode,
            errorMessage
        );

        webhookHistory.add(delivery);
        while (webhookHistory.size() > MAX_WEBHOOK_HISTORY) {
            webhookHistory.remove(0);
        }

        if (!success) {
            logger.warning("Webhook delivery failed: " + webhook.getId() + " - " + errorMessage);
        }
    }

    private String calculateSignature(String payload, String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256"));
            return "sha256=" + Base64.getEncoder().encodeToString(mac.doFinal(payload.getBytes()));
        } catch (Exception e) {
            return "";
        }
    }

    // === Custom Authentication Providers ===

    /**
     * Register a custom authentication provider.
     */
    public AuthProviderRegistrationResult registerAuthProvider(String pluginId,
                                                                CustomAuthProvider provider,
                                                                AuthProviderPriority priority) {
        // Validate plugin exists
        if (!registeredPlugins.containsKey(pluginId)) {
            return new AuthProviderRegistrationResult(false, null, "Plugin not registered: " + pluginId);
        }

        // Validate provider
        if (provider.getName() == null || provider.getName().isEmpty()) {
            return new AuthProviderRegistrationResult(false, null, "Provider name is required");
        }

        String providerId = pluginId + ":" + provider.getName();

        // Register provider
        authProviders.put(providerId, provider);
        authProviderPriorities.put(providerId, priority);

        logger.info("Auth provider registered: " + providerId + " with priority " + priority);

        return new AuthProviderRegistrationResult(true, providerId, "Auth provider registered successfully");
    }

    /**
     * Unregister an authentication provider.
     */
    public boolean unregisterAuthProvider(String providerId) {
        CustomAuthProvider provider = authProviders.remove(providerId);
        authProviderPriorities.remove(providerId);

        if (provider == null) {
            return false;
        }

        logger.info("Auth provider unregistered: " + providerId);
        return true;
    }

    /**
     * Get all registered auth providers, sorted by priority.
     */
    public List<CustomAuthProvider> getAuthProviders() {
        return authProviders.entrySet().stream()
            .sorted((a, b) -> {
                AuthProviderPriority pa = authProviderPriorities.getOrDefault(a.getKey(), AuthProviderPriority.NORMAL);
                AuthProviderPriority pb = authProviderPriorities.getOrDefault(b.getKey(), AuthProviderPriority.NORMAL);
                return Integer.compare(pb.getPriority(), pa.getPriority());
            })
            .map(Map.Entry::getValue)
            .toList();
    }

    /**
     * Authenticate using custom providers.
     */
    public CompletableFuture<CustomAuthResult> authenticateWithProviders(String username, String password, String ip) {
        List<CustomAuthProvider> providers = getAuthProviders();

        if (providers.isEmpty()) {
            return CompletableFuture.completedFuture(new CustomAuthResult(false, null, "No custom providers registered"));
        }

        // Try each provider in priority order
        for (CustomAuthProvider provider : providers) {
            try {
                CompletableFuture<CustomAuthResult> result = provider.authenticate(username, password, ip);
                Optional<CustomAuthResult> authResult = result.join() != null ? Optional.of(result.join()) : Optional.empty();

                if (authResult.isPresent() && authResult.get().isSuccess()) {
                    return result;
                }
            } catch (Exception e) {
                logger.warning("Error in auth provider " + provider.getName() + ": " + e.getMessage());
            }
        }

        return CompletableFuture.completedFuture(new CustomAuthResult(false, null, "Authentication failed with all providers"));
    }

    // === Public API ===

    /**
     * Validate an API key.
     */
    public ApiKeyValidationResult validateApiKey(String apiKey) {
        ApiKey key = apiKeys.get(apiKey);

        if (key == null) {
            return new ApiKeyValidationResult(false, null, "Invalid API key");
        }

        if (!key.isActive()) {
            return new ApiKeyValidationResult(false, null, "API key is disabled");
        }

        return new ApiKeyValidationResult(true, key, "API key is valid");
    }

    /**
     * Generate a new API key for a plugin.
     */
    public String generateNewApiKey(String pluginId) {
        RegisteredPlugin plugin = registeredPlugins.get(pluginId);
        if (plugin == null) {
            return null;
        }

        // Invalidate old key
        apiKeys.remove(plugin.getApiKey());

        // Generate new key
        String newKey = generateApiKey();
        apiKeys.put(newKey, new ApiKey(newKey, pluginId, plugin.getName(), System.currentTimeMillis(), true));

        // Update plugin
        plugin.setApiKey(newKey);

        return newKey;
    }

    /**
     * Revoke an API key.
     */
    public boolean revokeApiKey(String apiKey) {
        ApiKey key = apiKeys.get(apiKey);
        if (key == null) {
            return false;
        }

        key.setActive(false);
        return true;
    }

    // === Plugin Marketplace ===

    /**
     * Get available plugins from marketplace.
     */
    public List<MarketplacePlugin> getMarketplacePlugins() {
        // Check cache
        if (System.currentTimeMillis() - lastMarketplaceUpdate < MARKETPLACE_CACHE_TTL && !marketplaceCache.isEmpty()) {
            return new ArrayList<>(marketplaceCache.values());
        }

        // In a real implementation, this would fetch from a remote server
        // For now, return sample plugins
        loadSampleMarketplacePlugins();

        return new ArrayList<>(marketplaceCache.values());
    }

    private void loadSampleMarketplacePlugins() {
        marketplaceCache.clear();

        marketplaceCache.put("authcraft-discord-bridge", new MarketplacePlugin(
            "authcraft-discord-bridge",
            "Discord Bridge",
            "1.0.0",
            "Bridge between AuthCraft and Discord for enhanced 2FA",
            "AuthCraft Team",
            "https://authcraft.example.com/plugins/discord-bridge",
            "https://authcraft.example.com/plugins/discord-bridge/download",
            Arrays.asList("authcraft-core"),
            4.8,
            1250,
            true
        ));

        marketplaceCache.put("authcraft-geolocation", new MarketplacePlugin(
            "authcraft-geolocation",
            "GeoLocation Extension",
            "1.2.0",
            "Advanced geolocation features with IP mapping",
            "AuthCraft Team",
            "https://authcraft.example.com/plugins/geolocation",
            "https://authcraft.example.com/plugins/geolocation/download",
            Arrays.asList("authcraft-core"),
            4.5,
            890,
            true
        ));

        marketplaceCache.put("authcraft-advanced-logs", new MarketplacePlugin(
            "authcraft-advanced-logs",
            "Advanced Logging",
            "2.0.0",
            "Extended logging with external services integration",
            "Community",
            "https://authcraft.example.com/plugins/advanced-logs",
            "https://authcraft.example.com/plugins/advanced-logs/download",
            Arrays.asList("authcraft-core"),
            4.2,
            456,
            true
        ));

        lastMarketplaceUpdate = System.currentTimeMillis();
    }

    // === Utility Methods ===

    private String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;

            sb.append("\"").append(entry.getKey()).append("\":");

            Object value = entry.getValue();
            if (value == null) {
                sb.append("null");
            } else if (value instanceof String) {
                sb.append("\"").append(escapeJson((String) value)).append("\"");
            } else if (value instanceof Number || value instanceof Boolean) {
                sb.append(value);
            } else {
                sb.append("\"").append(escapeJson(value.toString())).append("\"");
            }
        }

        sb.append("}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // === Data Classes ===

    public static class PluginDescriptor {
        private String name;
        private String version;
        private String description;
        private String author;
        private Object mainClass;
        private List<String> dependencies = new ArrayList<>();

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public String getAuthor() { return author; }
        public void setAuthor(String author) { this.author = author; }
        public Object getMainClass() { return mainClass; }
        public void setMainClass(Object mainClass) { this.mainClass = mainClass; }
        public List<String> getDependencies() { return dependencies; }
        public void setDependencies(List<String> dependencies) { this.dependencies = dependencies; }
    }

    public static class RegisteredPlugin {
        private final String id;
        private final String name;
        private final String version;
        private final String description;
        private final String author;
        private final Object mainClass;
        private final List<String> dependencies;
        private final long registeredAt;
        private String apiKey;

        public RegisteredPlugin(String id, String name, String version, String description,
                                String author, Object mainClass, List<String> dependencies,
                                long registeredAt, String apiKey) {
            this.id = id;
            this.name = name;
            this.version = version;
            this.description = description;
            this.author = author;
            this.mainClass = mainClass;
            this.dependencies = dependencies;
            this.registeredAt = registeredAt;
            this.apiKey = apiKey;
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getVersion() { return version; }
        public String getDescription() { return description; }
        public String getAuthor() { return author; }
        public Object getMainClass() { return mainClass; }
        public List<String> getDependencies() { return dependencies; }
        public long getRegisteredAt() { return registeredAt; }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    }

    public static class PluginRegistrationResult {
        private final boolean success;
        private final String pluginId;
        private final String message;
        private final String apiKey;

        public PluginRegistrationResult(boolean success, String pluginId, String message) {
            this(success, pluginId, message, null);
        }

        public PluginRegistrationResult(boolean success, String pluginId, String message, String apiKey) {
            this.success = success;
            this.pluginId = pluginId;
            this.message = message;
            this.apiKey = apiKey;
        }

        public boolean isSuccess() { return success; }
        public String getPluginId() { return pluginId; }
        public String getMessage() { return message; }
        public String getApiKey() { return apiKey; }
    }

    public static class EventListener<T> {
        private final String pluginId;
        private final AuthCraftEvent.EventType eventType;
        private final Class<T> eventClass;
        private final Consumer<AuthCraftEvent<T>> handler;

        public EventListener(String pluginId, AuthCraftEvent.EventType eventType,
                             Class<T> eventClass, Consumer<AuthCraftEvent<T>> handler) {
            this.pluginId = pluginId;
            this.eventType = eventType;
            this.eventClass = eventClass;
            this.handler = handler;
        }

        public String getPluginId() { return pluginId; }
        public AuthCraftEvent.EventType getEventType() { return eventType; }
        public Class<T> getEventClass() { return eventClass; }
        public Consumer<AuthCraftEvent<T>> getHandler() { return handler; }
    }

    public static class AuthCraftEvent<T> {
        public enum EventType {
            PLAYER_LOGIN,
            PLAYER_LOGOUT,
            PLAYER_REGISTER,
            PLAYER_AUTHENTICATED,
            PLAYER_2FA_ENABLED,
            PLAYER_2FA_DISABLED,
            PLAYER_PASSWORD_CHANGED,
            PLAYER_ACCOUNT_LOCKED,
            PLAYER_ACCOUNT_UNLOCKED,
            SECURITY_ALERT,
            BOT_DETECTED,
            THREAT_DETECTED,
            SESSION_CREATED,
            SESSION_EXPIRED,
            WEBHOOK_RECEIVED,
            PLUGIN_REGISTERED,
            PLUGIN_UNREGISTERED,
            CUSTOM
        }

        private final EventType type;
        private final T data;
        private final long timestamp;

        public AuthCraftEvent(EventType type, T data, long timestamp) {
            this.type = type;
            this.data = data;
            this.timestamp = timestamp;
        }

        public EventType getType() { return type; }
        public T getData() { return data; }
        public long getTimestamp() { return timestamp; }
    }

    public static class WebhookConfig {
        private String url;
        private String secret;
        private List<AuthCraftEvent.EventType> events = new ArrayList<>();
        private Map<String, String> headers = new HashMap<>();

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
        public List<AuthCraftEvent.EventType> getEvents() { return events; }
        public void setEvents(List<AuthCraftEvent.EventType> events) { this.events = events; }
        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers; }
    }

    public static class WebhookEndpoint {
        private final String id;
        private final String pluginId;
        private final String url;
        private final String secret;
        private final List<AuthCraftEvent.EventType> events;
        private final Map<String, String> headers;
        private boolean enabled;
        private final long createdAt;

        public WebhookEndpoint(String id, String pluginId, String url, String secret,
                               List<AuthCraftEvent.EventType> events, Map<String, String> headers,
                               boolean enabled, long createdAt) {
            this.id = id;
            this.pluginId = pluginId;
            this.url = url;
            this.secret = secret;
            this.events = events;
            this.headers = headers;
            this.enabled = enabled;
            this.createdAt = createdAt;
        }

        public String getId() { return id; }
        public String getPluginId() { return pluginId; }
        public String getUrl() { return url; }
        public String getSecret() { return secret; }
        public List<AuthCraftEvent.EventType> getEvents() { return events; }
        public Map<String, String> getHeaders() { return headers; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public long getCreatedAt() { return createdAt; }
    }

    public static class WebhookRegistrationResult {
        private final boolean success;
        private final String webhookId;
        private final String message;

        public WebhookRegistrationResult(boolean success, String webhookId, String message) {
            this.success = success;
            this.webhookId = webhookId;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getWebhookId() { return webhookId; }
        public String getMessage() { return message; }
    }

    public static class WebhookDelivery {
        private final String id;
        private final String webhookId;
        private final AuthCraftEvent.EventType eventType;
        private final long timestamp;
        private final long durationMs;
        private final boolean success;
        private final int responseCode;
        private final String errorMessage;

        public WebhookDelivery(String id, String webhookId, AuthCraftEvent.EventType eventType,
                               long timestamp, long durationMs, boolean success,
                               int responseCode, String errorMessage) {
            this.id = id;
            this.webhookId = webhookId;
            this.eventType = eventType;
            this.timestamp = timestamp;
            this.durationMs = durationMs;
            this.success = success;
            this.responseCode = responseCode;
            this.errorMessage = errorMessage;
        }

        public String getId() { return id; }
        public String getWebhookId() { return webhookId; }
        public AuthCraftEvent.EventType getEventType() { return eventType; }
        public long getTimestamp() { return timestamp; }
        public long getDurationMs() { return durationMs; }
        public boolean isSuccess() { return success; }
        public int getResponseCode() { return responseCode; }
        public String getErrorMessage() { return errorMessage; }
    }

    public static class CustomAuthProvider {
        private final String name;
        private final String pluginId;

        public CustomAuthProvider(String name, String pluginId) {
            this.name = name;
            this.pluginId = pluginId;
        }

        public String getName() { return name; }
        public String getPluginId() { return pluginId; }

        public CompletableFuture<CustomAuthResult> authenticate(String username, String password, String ip) {
            // Override in subclass
            return CompletableFuture.completedFuture(new CustomAuthResult(false, null, "Not implemented"));
        }
    }

    public static class AuthProviderPriority {
        public static final AuthProviderPriority HIGHEST = new AuthProviderPriority(100);
        public static final AuthProviderPriority HIGH = new AuthProviderPriority(75);
        public static final AuthProviderPriority NORMAL = new AuthProviderPriority(50);
        public static final AuthProviderPriority LOW = new AuthProviderPriority(25);
        public static final AuthProviderPriority LOWEST = new AuthProviderPriority(0);

        private final int priority;

        public AuthProviderPriority(int priority) {
            this.priority = priority;
        }

        public int getPriority() { return priority; }
    }

    public static class AuthProviderRegistrationResult {
        private final boolean success;
        private final String providerId;
        private final String message;

        public AuthProviderRegistrationResult(boolean success, String providerId, String message) {
            this.success = success;
            this.providerId = providerId;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getProviderId() { return providerId; }
        public String getMessage() { return message; }
    }

    public static class CustomAuthResult {
        private final boolean success;
        private final Account account;
        private final String message;

        public CustomAuthResult(boolean success, Account account, String message) {
            this.success = success;
            this.account = account;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public Account getAccount() { return account; }
        public String getMessage() { return message; }
    }

    public static class ApiKey {
        private final String key;
        private final String pluginId;
        private final String pluginName;
        private final long createdAt;
        private boolean active;

        public ApiKey(String key, String pluginId, String pluginName, long createdAt, boolean active) {
            this.key = key;
            this.pluginId = pluginId;
            this.pluginName = pluginName;
            this.createdAt = createdAt;
            this.active = active;
        }

        public String getKey() { return key; }
        public String getPluginId() { return pluginId; }
        public String getPluginName() { return pluginName; }
        public long getCreatedAt() { return createdAt; }
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
    }

    public static class ApiKeyValidationResult {
        private final boolean valid;
        private final ApiKey apiKey;
        private final String message;

        public ApiKeyValidationResult(boolean valid, ApiKey apiKey, String message) {
            this.valid = valid;
            this.apiKey = apiKey;
            this.message = message;
        }

        public boolean isValid() { return valid; }
        public ApiKey getApiKey() { return apiKey; }
        public String getMessage() { return message; }
    }

    public static class MarketplacePlugin {
        private final String id;
        private final String name;
        private final String version;
        private final String description;
        private final String author;
        private final String infoUrl;
        private final String downloadUrl;
        private final List<String> dependencies;
        private final double rating;
        private final int downloads;
        private final boolean verified;

        public MarketplacePlugin(String id, String name, String version, String description,
                                 String author, String infoUrl, String downloadUrl,
                                 List<String> dependencies, double rating, int downloads, boolean verified) {
            this.id = id;
            this.name = name;
            this.version = version;
            this.description = description;
            this.author = author;
            this.infoUrl = infoUrl;
            this.downloadUrl = downloadUrl;
            this.dependencies = dependencies;
            this.rating = rating;
            this.downloads = downloads;
            this.verified = verified;
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getVersion() { return version; }
        public String getDescription() { return description; }
        public String getAuthor() { return author; }
        public String getInfoUrl() { return infoUrl; }
        public String getDownloadUrl() { return downloadUrl; }
        public List<String> getDependencies() { return dependencies; }
        public double getRating() { return rating; }
        public int getDownloads() { return downloads; }
        public boolean isVerified() { return verified; }
    }
}
