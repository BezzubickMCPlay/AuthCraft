// com/authcraft/core/sync/RedisSyncService.java
package com.authcraft.core.sync;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.Session;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.core.service.AuditService;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisPubSub;
import redis.clients.jedis.exceptions.JedisException;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Redis-based Multi-Server Synchronization Service.
 * 
 * Features:
 * - Redis-based session sharing across servers
 * - Cross-server authentication state sync
 * - Global ban list synchronization
 * - Centralized configuration management
 * - Real-time sync of 2FA states
 * - Pub/Sub messaging for real-time events
 */
public class RedisSyncService {

    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final AuditService auditService;
    private final Logger logger;

    // Redis connection pool
    private JedisPool jedisPool;

    // Jackson ObjectMapper for JSON serialization
    private final ObjectMapper objectMapper;

    // Background executor for async operations
    private final ScheduledExecutorService executor;

    // Pub/Sub listener thread
    private Thread pubSubThread;
    private final AtomicBoolean running = new AtomicBoolean(false);

    // Local cache for quick lookups (invalidated on sync)
    private final Map<UUID, Session> localSessionCache = new ConcurrentHashMap<>();
    private final Map<String, BanEntry> globalBanCache = new ConcurrentHashMap<>();
    private final Map<UUID, Set<TwoFactorMethod>> twoFactorStateCache = new ConcurrentHashMap<>();

    // Sync statistics
    private final AtomicBoolean isConnected = new AtomicBoolean(false);
    private long lastSyncTime = 0;
    private int syncCount = 0;

    // Redis key prefixes
    private static final String SESSION_PREFIX = "authcraft:session:";
    private static final String ACCOUNT_PREFIX = "authcraft:account:";
    private static final String BAN_PREFIX = "authcraft:ban:";
    private static final String TWOFCTOR_PREFIX = "authcraft:2fa:";
    private static final String CONFIG_PREFIX = "authcraft:config:";
    private static final String SERVER_PREFIX = "authcraft:server:";

    // Pub/Sub channels
    private static final String CHANNEL_SESSION = "authcraft:channel:session";
    private static final String CHANNEL_AUTH = "authcraft:channel:auth";
    private static final String CHANNEL_BAN = "authcraft:channel:ban";
    private static final String CHANNEL_2FA = "authcraft:channel:2fa";
    private static final String CHANNEL_CONFIG = "authcraft:channel:config";

    // Server identification
    private final String serverId;

    /**
     * Creates a new RedisSyncService.
     */
    public RedisSyncService(AuthCraftConfig config, PlatformAdapter platform, AuditService auditService) {
        this.config = config;
        this.platform = platform;
        this.auditService = auditService;
        this.logger = platform.getLogger();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.executor = Executors.newScheduledThreadPool(2);
        this.serverId = UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Initialize Redis connection and start sync services.
     */
    public boolean initialize() {
        if (!config.isRedisSyncEnabled()) {
            logger.info("Redis sync is disabled in configuration");
            return false;
        }

        try {
            // Create Redis connection pool
            JedisPoolConfig poolConfig = new JedisPoolConfig();
            poolConfig.setMaxTotal(config.getRedisMaxConnections());
            poolConfig.setMaxIdle(config.getRedisMaxIdle());
            poolConfig.setMinIdle(config.getRedisMinIdle());
            poolConfig.setTestOnBorrow(true);
            poolConfig.setTestWhileIdle(true);

            String host = config.getRedisHost();
            int port = config.getRedisPort();
            String password = config.getRedisPassword();
            int database = config.getRedisDatabase();

            if (password != null && !password.isEmpty()) {
                jedisPool = new JedisPool(poolConfig, host, port, 
                    config.getRedisTimeoutMs(), password, database);
            } else {
                jedisPool = new JedisPool(poolConfig, host, port, 
                    config.getRedisTimeoutMs(), null, database);
            }

            // Test connection
            try (Jedis jedis = jedisPool.getResource()) {
                jedis.ping();
                isConnected.set(true);
                logger.info("Connected to Redis at " + host + ":" + port);
            }

            // Start Pub/Sub listener
            startPubSubListener();

            // Start periodic sync tasks
            startSyncTasks();

            // Register this server
            registerServer();

            return true;

        } catch (Exception e) {
            logger.severe("Failed to connect to Redis: " + e.getMessage());
            isConnected.set(false);
            return false;
        }
    }

    /**
     * Shutdown Redis sync service.
     */
    public void shutdown() {
        running.set(false);

        // Unregister this server
        unregisterServer();

        // Stop Pub/Sub thread
        if (pubSubThread != null) {
            pubSubThread.interrupt();
        }

        // Shutdown executor
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }

        // Close Redis pool
        if (jedisPool != null) {
            jedisPool.close();
        }

        isConnected.set(false);
        logger.info("Redis sync service shutdown complete");
    }

    // === Session Synchronization ===

    /**
     * Publish session to Redis for cross-server sync.
     */
    public void publishSession(Session session) {
        if (!isConnected.get()) return;

        try {
            String json = objectMapper.writeValueAsString(session);
            String key = SESSION_PREFIX + session.getPlayerUuid().toString();

            try (Jedis jedis = jedisPool.getResource()) {
                jedis.setex(key, (int) TimeUnit.HOURS.toSeconds(config.getSessionTtlHours()), json);
                jedis.publish(CHANNEL_SESSION, createMessage("SESSION_CREATE", json));
            }

            localSessionCache.put(session.getPlayerUuid(), session);
            logger.fine("Published session for " + session.getPlayerUuid());

        } catch (Exception e) {
            logger.warning("Failed to publish session: " + e.getMessage());
        }
    }

    /**
     * Get session from Redis (cross-server lookup).
     */
    public Optional<Session> getSession(UUID playerUuid) {
        // Check local cache first
        Session cached = localSessionCache.get(playerUuid);
        if (cached != null && cached.isValid()) {
            return Optional.of(cached);
        }

        if (!isConnected.get()) return Optional.empty();

        try {
            String key = SESSION_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                String json = jedis.get(key);
                if (json != null) {
                    Session session = objectMapper.readValue(json, Session.class);
                    localSessionCache.put(playerUuid, session);
                    return Optional.of(session);
                }
            }
        } catch (Exception e) {
            logger.warning("Failed to get session from Redis: " + e.getMessage());
        }

        return Optional.empty();
    }

    /**
     * Invalidate session across all servers.
     */
    public void invalidateSession(UUID playerUuid) {
        if (!isConnected.get()) return;

        try {
            String key = SESSION_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                jedis.del(key);
                jedis.publish(CHANNEL_SESSION, createMessage("SESSION_INVALIDATE", 
                    playerUuid.toString()));
            }

            localSessionCache.remove(playerUuid);
            logger.fine("Invalidated session for " + playerUuid);

        } catch (Exception e) {
            logger.warning("Failed to invalidate session: " + e.getMessage());
        }
    }

    // === Authentication State Sync ===

    /**
     * Publish authentication event to other servers.
     */
    public void publishAuthState(UUID playerUuid, String username, boolean authenticated, 
                                  String serverName) {
        if (!isConnected.get()) return;

        try {
            Map<String, Object> data = new HashMap<>();
            data.put("uuid", playerUuid.toString());
            data.put("username", username);
            data.put("authenticated", authenticated);
            data.put("server", serverName);
            data.put("timestamp", System.currentTimeMillis());

            String json = objectMapper.writeValueAsString(data);

            try (Jedis jedis = jedisPool.getResource()) {
                jedis.publish(CHANNEL_AUTH, createMessage("AUTH_STATE", json));
                
                // Also store current server for player
                if (authenticated) {
                    jedis.hset("authcraft:online_players", playerUuid.toString(), serverId);
                } else {
                    jedis.hdel("authcraft:online_players", playerUuid.toString());
                }
            }

            logger.fine("Published auth state for " + username);

        } catch (Exception e) {
            logger.warning("Failed to publish auth state: " + e.getMessage());
        }
    }

    /**
     * Check if player is authenticated on any server.
     */
    public boolean isAuthenticatedAnywhere(UUID playerUuid) {
        if (!isConnected.get()) return false;

        try (Jedis jedis = jedisPool.getResource()) {
            return jedis.hexists("authcraft:online_players", playerUuid.toString());
        } catch (Exception e) {
            logger.warning("Failed to check auth state: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get the server where a player is currently online.
     */
    public Optional<String> getPlayerServer(UUID playerUuid) {
        if (!isConnected.get()) return Optional.empty();

        try (Jedis jedis = jedisPool.getResource()) {
            String server = jedis.hget("authcraft:online_players", playerUuid.toString());
            return Optional.ofNullable(server);
        } catch (Exception e) {
            logger.warning("Failed to get player server: " + e.getMessage());
            return Optional.empty();
        }
    }

    // === Global Ban List Synchronization ===

    /**
     * Add a global ban.
     */
    public void addGlobalBan(UUID playerUuid, String reason, String bannedBy, long expiresAt) {
        if (!isConnected.get()) return;

        try {
            BanEntry ban = new BanEntry(playerUuid, reason, bannedBy, 
                System.currentTimeMillis(), expiresAt);
            String json = objectMapper.writeValueAsString(ban);
            String key = BAN_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                if (expiresAt > 0) {
                    long ttl = (expiresAt - System.currentTimeMillis()) / 1000;
                    jedis.setex(key, (int) ttl, json);
                } else {
                    jedis.set(key, json);
                }
                jedis.publish(CHANNEL_BAN, createMessage("BAN_ADD", json));
            }

            globalBanCache.put(playerUuid.toString(), ban);
            logger.info("Added global ban for " + playerUuid + ": " + reason);

        } catch (Exception e) {
            logger.warning("Failed to add global ban: " + e.getMessage());
        }
    }

    /**
     * Remove a global ban.
     */
    public void removeGlobalBan(UUID playerUuid) {
        if (!isConnected.get()) return;

        try {
            String key = BAN_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                jedis.del(key);
                jedis.publish(CHANNEL_BAN, createMessage("BAN_REMOVE", 
                    playerUuid.toString()));
            }

            globalBanCache.remove(playerUuid.toString());
            logger.info("Removed global ban for " + playerUuid);

        } catch (Exception e) {
            logger.warning("Failed to remove global ban: " + e.getMessage());
        }
    }

    /**
     * Check if player is globally banned.
     */
    public Optional<BanEntry> getGlobalBan(UUID playerUuid) {
        // Check cache first
        BanEntry cached = globalBanCache.get(playerUuid.toString());
        if (cached != null) {
            if (cached.expiresAt > 0 && cached.expiresAt < System.currentTimeMillis()) {
                globalBanCache.remove(playerUuid.toString());
                return Optional.empty();
            }
            return Optional.of(cached);
        }

        if (!isConnected.get()) return Optional.empty();

        try {
            String key = BAN_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                String json = jedis.get(key);
                if (json != null) {
                    BanEntry ban = objectMapper.readValue(json, BanEntry.class);
                    globalBanCache.put(playerUuid.toString(), ban);
                    return Optional.of(ban);
                }
            }
        } catch (Exception e) {
            logger.warning("Failed to check global ban: " + e.getMessage());
        }

        return Optional.empty();
    }

    /**
     * Get all global bans.
     */
    public List<BanEntry> getAllGlobalBans() {
        List<BanEntry> bans = new ArrayList<>();

        if (!isConnected.get()) return bans;

        try (Jedis jedis = jedisPool.getResource()) {
            Set<String> keys = jedis.keys(BAN_PREFIX + "*");
            for (String key : keys) {
                String json = jedis.get(key);
                if (json != null) {
                    bans.add(objectMapper.readValue(json, BanEntry.class));
                }
            }
        } catch (Exception e) {
            logger.warning("Failed to get all global bans: " + e.getMessage());
        }

        return bans;
    }

    // === 2FA State Synchronization ===

    /**
     * Sync 2FA enabled state.
     */
    public void syncTwoFactorState(UUID playerUuid, Set<TwoFactorMethod> enabledMethods) {
        if (!isConnected.get()) return;

        try {
            Map<String, Object> data = new HashMap<>();
            data.put("uuid", playerUuid.toString());
            data.put("methods", enabledMethods.stream()
                .map(TwoFactorMethod::name).toList());
            data.put("timestamp", System.currentTimeMillis());

            String json = objectMapper.writeValueAsString(data);
            String key = TWOFCTOR_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                jedis.set(key, json);
                jedis.publish(CHANNEL_2FA, createMessage("2FA_UPDATE", json));
            }

            twoFactorStateCache.put(playerUuid, enabledMethods);
            logger.fine("Synced 2FA state for " + playerUuid);

        } catch (Exception e) {
            logger.warning("Failed to sync 2FA state: " + e.getMessage());
        }
    }

    /**
     * Get 2FA state from Redis.
     */
    public Optional<Set<TwoFactorMethod>> getTwoFactorState(UUID playerUuid) {
        // Check cache first
        Set<TwoFactorMethod> cached = twoFactorStateCache.get(playerUuid);
        if (cached != null) {
            return Optional.of(cached);
        }

        if (!isConnected.get()) return Optional.empty();

        try {
            String key = TWOFCTOR_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                String json = jedis.get(key);
                if (json != null) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> data = objectMapper.readValue(json, Map.class);
                    List<String> methods = (List<String>) data.get("methods");
                    Set<TwoFactorMethod> result = new HashSet<>();
                    if (methods != null) {
                        for (String m : methods) {
                            try {
                                result.add(TwoFactorMethod.valueOf(m));
                            } catch (IllegalArgumentException ignored) {}
                        }
                    }
                    twoFactorStateCache.put(playerUuid, result);
                    return Optional.of(result);
                }
            }
        } catch (Exception e) {
            logger.warning("Failed to get 2FA state: " + e.getMessage());
        }

        return Optional.empty();
    }

    /**
     * Invalidate 2FA state (player disabled 2FA).
     */
    public void invalidateTwoFactorState(UUID playerUuid) {
        if (!isConnected.get()) return;

        try {
            String key = TWOFCTOR_PREFIX + playerUuid.toString();

            try (Jedis jedis = jedisPool.getResource()) {
                jedis.del(key);
                jedis.publish(CHANNEL_2FA, createMessage("2FA_INVALIDATE", 
                    playerUuid.toString()));
            }

            twoFactorStateCache.remove(playerUuid);
            logger.fine("Invalidated 2FA state for " + playerUuid);

        } catch (Exception e) {
            logger.warning("Failed to invalidate 2FA state: " + e.getMessage());
        }
    }

    // === Configuration Synchronization ===

    /**
     * Publish configuration update.
     */
    public void publishConfigUpdate(String key, String value) {
        if (!isConnected.get()) return;

        try {
            Map<String, Object> data = new HashMap<>();
            data.put("key", key);
            data.put("value", value);
            data.put("server", serverId);
            data.put("timestamp", System.currentTimeMillis());

            String json = objectMapper.writeValueAsString(data);

            try (Jedis jedis = jedisPool.getResource()) {
                jedis.hset(CONFIG_PREFIX + "shared", key, value);
                jedis.publish(CHANNEL_CONFIG, createMessage("CONFIG_UPDATE", json));
            }

            logger.fine("Published config update: " + key);

        } catch (Exception e) {
            logger.warning("Failed to publish config update: " + e.getMessage());
        }
    }

    /**
     * Get shared configuration value.
     */
    public Optional<String> getSharedConfig(String key) {
        if (!isConnected.get()) return Optional.empty();

        try (Jedis jedis = jedisPool.getResource()) {
            String value = jedis.hget(CONFIG_PREFIX + "shared", key);
            return Optional.ofNullable(value);
        } catch (Exception e) {
            logger.warning("Failed to get shared config: " + e.getMessage());
            return Optional.empty();
        }
    }

    // === Server Registry ===

    /**
     * Register this server in Redis.
     */
    private void registerServer() {
        if (!isConnected.get()) return;

        try (Jedis jedis = jedisPool.getResource()) {
            Map<String, String> serverInfo = new HashMap<>();
            serverInfo.put("id", serverId);
            serverInfo.put("name", platform.getServerName());
            serverInfo.put("started", String.valueOf(System.currentTimeMillis()));
            serverInfo.put("last_heartbeat", String.valueOf(System.currentTimeMillis()));

            jedis.hset(SERVER_PREFIX + serverId, serverInfo);
            jedis.sadd("authcraft:servers", serverId);
            logger.info("Registered server " + serverId + " in Redis");
        } catch (Exception e) {
            logger.warning("Failed to register server: " + e.getMessage());
        }
    }

    /**
     * Unregister this server from Redis.
     */
    private void unregisterServer() {
        if (!isConnected.get()) return;

        try (Jedis jedis = jedisPool.getResource()) {
            jedis.del(SERVER_PREFIX + serverId);
            jedis.srem("authcraft:servers", serverId);
            logger.info("Unregistered server " + serverId + " from Redis");
        } catch (Exception e) {
            logger.warning("Failed to unregister server: " + e.getMessage());
        }
    }

    /**
     * Update server heartbeat.
     */
    private void updateHeartbeat() {
        if (!isConnected.get()) return;

        try (Jedis jedis = jedisPool.getResource()) {
            jedis.hset(SERVER_PREFIX + serverId, "last_heartbeat", 
                String.valueOf(System.currentTimeMillis()));
        } catch (Exception e) {
            logger.warning("Failed to update heartbeat: " + e.getMessage());
        }
    }

    /**
     * Get all active servers.
     */
    public List<ServerInfo> getActiveServers() {
        List<ServerInfo> servers = new ArrayList<>();

        if (!isConnected.get()) return servers;

        try (Jedis jedis = jedisPool.getResource()) {
            Set<String> serverIds = jedis.smembers("authcraft:servers");
            long now = System.currentTimeMillis();
            long timeout = TimeUnit.MINUTES.toMillis(2);

            for (String id : serverIds) {
                Map<String, String> info = jedis.hgetAll(SERVER_PREFIX + id);
                if (!info.isEmpty()) {
                    long lastHeartbeat = Long.parseLong(info.getOrDefault(
                        "last_heartbeat", "0"));
                    if (now - lastHeartbeat < timeout) {
                        servers.add(new ServerInfo(
                            id,
                            info.getOrDefault("name", "unknown"),
                            Long.parseLong(info.getOrDefault("started", "0")),
                            lastHeartbeat
                        ));
                    }
                }
            }
        } catch (Exception e) {
            logger.warning("Failed to get active servers: " + e.getMessage());
        }

        return servers;
    }

    // === Pub/Sub Handling ===

    /**
     * Start Pub/Sub listener thread.
     */
    private void startPubSubListener() {
        running.set(true);
        pubSubThread = new Thread(() -> {
            while (running.get() && !Thread.currentThread().isInterrupted()) {
                try (Jedis jedis = jedisPool.getResource()) {
                    jedis.subscribe(new JedisPubSub() {
                        @Override
                        public void onMessage(String channel, String message) {
                            handlePubSubMessage(channel, message);
                        }
                    }, CHANNEL_SESSION, CHANNEL_AUTH, CHANNEL_BAN, CHANNEL_2FA, CHANNEL_CONFIG);
                } catch (JedisException e) {
                    if (running.get()) {
                        logger.warning("Pub/Sub connection lost, reconnecting: " + e.getMessage());
                        try {
                            Thread.sleep(5000);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
            }
        }, "Redis-PubSub-Listener");
        pubSubThread.setDaemon(true);
        pubSubThread.start();
    }

    /**
     * Handle incoming Pub/Sub message.
     */
    private void handlePubSubMessage(String channel, String message) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> data = objectMapper.readValue(message, Map.class);
            String type = (String) data.get("type");
            String payload = (String) data.get("payload");

            switch (channel) {
                case CHANNEL_SESSION:
                    handleSessionMessage(type, payload);
                    break;
                case CHANNEL_AUTH:
                    handleAuthMessage(type, payload);
                    break;
                case CHANNEL_BAN:
                    handleBanMessage(type, payload);
                    break;
                case CHANNEL_2FA:
                    handleTwoFactorMessage(type, payload);
                    break;
                case CHANNEL_CONFIG:
                    handleConfigMessage(type, payload);
                    break;
            }
        } catch (Exception e) {
            logger.warning("Failed to handle Pub/Sub message: " + e.getMessage());
        }
    }

    private void handleSessionMessage(String type, String payload) {
        switch (type) {
            case "SESSION_CREATE":
                // Another server created a session
                break;
            case "SESSION_INVALIDATE":
                UUID uuid = UUID.fromString(payload);
                localSessionCache.remove(uuid);
                platform.runSync(() -> {
                    // Notify local server to invalidate session
                    platform.sendMessage(uuid, "Your session has been invalidated from another server.");
                });
                break;
        }
    }

    private void handleAuthMessage(String type, String payload) {
        // Handle auth state changes from other servers
        logger.fine("Received auth message: " + type);
    }

    private void handleBanMessage(String type, String payload) {
        try {
            switch (type) {
                case "BAN_ADD":
                    BanEntry ban = objectMapper.readValue(payload, BanEntry.class);
                    globalBanCache.put(ban.playerUuid.toString(), ban);
                    // Check if player is on this server and kick them
                    platform.runSync(() -> {
                        if (platform.isPlayerOnline(ban.playerUuid)) {
                            platform.kickPlayer(ban.playerUuid, 
                                "You have been globally banned: " + ban.reason);
                        }
                    });
                    break;
                case "BAN_REMOVE":
                    UUID uuid = UUID.fromString(payload);
                    globalBanCache.remove(uuid.toString());
                    break;
            }
        } catch (Exception e) {
            logger.warning("Failed to handle ban message: " + e.getMessage());
        }
    }

    private void handleTwoFactorMessage(String type, String payload) {
        switch (type) {
            case "2FA_UPDATE":
                // 2FA state updated on another server
                break;
            case "2FA_INVALIDATE":
                UUID uuid = UUID.fromString(payload);
                twoFactorStateCache.remove(uuid);
                break;
        }
    }

    private void handleConfigMessage(String type, String payload) {
        // Handle config updates from other servers
        logger.fine("Received config message: " + type);
    }

    // === Background Tasks ===

    /**
     * Start periodic sync tasks.
     */
    private void startSyncTasks() {
        // Heartbeat task
        executor.scheduleAtFixedRate(this::updateHeartbeat, 
            0, 30, TimeUnit.SECONDS);

        // Cache cleanup task
        executor.scheduleAtFixedRate(this::cleanupCaches, 
            1, 5, TimeUnit.MINUTES);

        // Sync statistics task
        executor.scheduleAtFixedRate(this::updateSyncStats, 
            1, 1, TimeUnit.MINUTES);
    }

    /**
     * Cleanup expired entries from local caches.
     */
    private void cleanupCaches() {
        // Cleanup session cache
        localSessionCache.entrySet().removeIf(e -> !e.getValue().isValid());

        // Cleanup ban cache
        long now = System.currentTimeMillis();
        globalBanCache.entrySet().removeIf(e ->
            e.getValue().expiresAt > 0 && e.getValue().expiresAt < now);

        logger.fine("Cache cleanup completed");
    }

    /**
     * Update sync statistics.
     */
    private void updateSyncStats() {
        lastSyncTime = System.currentTimeMillis();
        syncCount++;
    }

    // === Utility Methods ===

    private String createMessage(String type, String payload) {
        try {
            Map<String, Object> msg = new HashMap<>();
            msg.put("type", type);
            msg.put("payload", payload);
            msg.put("server", serverId);
            msg.put("timestamp", System.currentTimeMillis());
            return objectMapper.writeValueAsString(msg);
        } catch (Exception e) {
            return "{}";
        }
    }

    public boolean isConnected() {
        return isConnected.get();
    }

    public String getServerId() {
        return serverId;
    }

    public long getLastSyncTime() {
        return lastSyncTime;
    }

    public int getSyncCount() {
        return syncCount;
    }

    // === Data Classes ===

    /**
     * Represents a global ban entry.
     */
    public static class BanEntry {
        public UUID playerUuid;
        public String reason;
        public String bannedBy;
        public long bannedAt;
        public long expiresAt; // 0 = permanent

        public BanEntry() {}

        public BanEntry(UUID playerUuid, String reason, String bannedBy, 
                        long bannedAt, long expiresAt) {
            this.playerUuid = playerUuid;
            this.reason = reason;
            this.bannedBy = bannedBy;
            this.bannedAt = bannedAt;
            this.expiresAt = expiresAt;
        }

        public boolean isPermanent() {
            return expiresAt == 0;
        }

        public boolean isExpired() {
            return expiresAt > 0 && expiresAt < System.currentTimeMillis();
        }
    }

    /**
     * Represents server information.
     */
    public static class ServerInfo {
        public String id;
        public String name;
        public long startedAt;
        public long lastHeartbeat;

        public ServerInfo(String id, String name, long startedAt, long lastHeartbeat) {
            this.id = id;
            this.name = name;
            this.startedAt = startedAt;
            this.lastHeartbeat = lastHeartbeat;
        }

        public boolean isActive() {
            return System.currentTimeMillis() - lastHeartbeat < 
                TimeUnit.MINUTES.toMillis(2);
        }
    }
}
