package com.authcraft.core;

import com.authcraft.core.api.*;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.crypto.*;
import com.authcraft.core.model.*;
import com.authcraft.core.service.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class AuthCraftCore {

    private static AuthCraftCore instance;

    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final StorageProvider storage;
    private final Logger logger;

    private final AuthService authService;
    private final SessionService sessionService;
    private final PasswordValidator passwordValidator;
    private final RoleService roleService;
    private final AuditService auditService;
    private final TwoFactorService twoFactorService;
    private final MessageService messageService;
    private final BackupService backupService;

    private final Map<String, HashingStrategy> hashingStrategies;
    private final HashingStrategy primaryHasher;
    private final Map<TwoFactorMethod, TwoFactorProvider> twoFactorProviders;

    private final Set<UUID> authenticatedPlayers;
    private final Set<UUID> limboPlayers;

    public AuthCraftCore(AuthCraftConfig config,
                         PlatformAdapter platform,
                         StorageProvider storage,
                         List<TwoFactorProvider> providers) {
        instance = this;
        this.config = config;
        this.platform = platform;
        this.storage = storage;
        this.logger = platform.getLogger();

        this.authenticatedPlayers = ConcurrentHashMap.newKeySet();
        this.limboPlayers = ConcurrentHashMap.newKeySet();

        // Hashing
        this.hashingStrategies = new HashMap<>();
        registerHasher(new Argon2idHasher(config));
        registerHasher(new BCryptHasher(config));
        registerHasher(new PBKDF2Hasher(config));
        registerHasher(new LegacySHA256Hasher());
        registerHasher(new LegacyMD5Hasher());

        this.primaryHasher = hashingStrategies.get(config.getHashAlgorithm().getId());
        if (primaryHasher == null) {
            throw new IllegalStateException(
                    "Primary hash algorithm not found: " + config.getHashAlgorithm().getId());
        }

        // 2FA
        this.twoFactorProviders = new HashMap<>();
        for (TwoFactorProvider provider : providers) {
            if (provider.isAvailable()) {
                twoFactorProviders.put(provider.getMethod(), provider);
                logger.info("[AuthCraft] 2FA provider: " + provider.getMethod());
            }
        }

        // Services (order matters — dependencies)
        this.messageService = new MessageService(platform, config);

        PasswordBlacklist blacklist = new PasswordBlacklist(
                logger, platform.getDataFolder(), false);
        this.passwordValidator = new PasswordValidator(config, blacklist);

        this.auditService = new AuditService(storage, platform, config);
        this.sessionService = new SessionService(storage, config);
        this.twoFactorService = new TwoFactorService(storage, twoFactorProviders, config);
        this.roleService = new RoleService(platform, config);
        this.backupService = new BackupService(storage, platform, config);

        this.authService = new AuthService(
                this, config, storage, platform,
                passwordValidator, sessionService,
                auditService, twoFactorService, roleService
        );

        logger.info("[AuthCraft] Core initialized");
    }

    private void registerHasher(HashingStrategy strategy) {
        hashingStrategies.put(strategy.getAlgorithmId(), strategy);
    }

    public void enable() {
        storage.initialize().thenRun(() -> {
            logger.info("[AuthCraft] Storage initialized");
            platform.scheduleRepeating(
                    () -> sessionService.cleanupExpiredSessions(),
                    20L * 60 * config.getSessionCleanupIntervalMinutes(),
                    20L * 60 * config.getSessionCleanupIntervalMinutes()
            );
            backupService.scheduleAutoBackups();
        }).exceptionally(ex -> {
            logger.severe("[AuthCraft] Storage init failed: " + ex.getMessage());
            return null;
        });
    }

    public void disable() {
        authenticatedPlayers.clear();
        limboPlayers.clear();
        auditService.shutdown();
        storage.shutdown().join();
        logger.info("[AuthCraft] Disabled");
    }

    // === Player State ===
    public boolean isAuthenticated(UUID uuid) { return authenticatedPlayers.contains(uuid); }
    public void setAuthenticated(UUID uuid, boolean state) {
        if (state) { authenticatedPlayers.add(uuid); limboPlayers.remove(uuid); }
        else { authenticatedPlayers.remove(uuid); }
    }
    public boolean isInLimbo(UUID uuid) { return limboPlayers.contains(uuid); }
    public void setInLimbo(UUID uuid, boolean state) {
        if (state) limboPlayers.add(uuid); else limboPlayers.remove(uuid);
    }

    public void handlePlayerJoin(UUID uuid, String username, String ip) {
        platform.runAsync(() -> authService.handleJoin(uuid, username, ip));
    }

    public void handlePlayerQuit(UUID uuid) {
        authenticatedPlayers.remove(uuid);
        limboPlayers.remove(uuid);
    }

    // === Hashing ===
    public String hashPassword(String password) { return primaryHasher.hash(password); }

    public boolean verifyPassword(String password, String hash, HashAlgorithm algorithm) {
        HashingStrategy strategy = hashingStrategies.get(algorithm.getId());
        if (strategy == null) { logger.warning("[AuthCraft] Unknown algorithm: " + algorithm.getId()); return false; }
        return strategy.verify(password, hash);
    }

    public boolean needsRehash(String hash, HashAlgorithm algorithm) {
        if (algorithm.isLegacy()) return true;
        if (algorithm != config.getHashAlgorithm()) return true;
        return primaryHasher.needsRehash(hash);
    }

    // === Getters ===
    public static AuthCraftCore getInstance() { return instance; }
    public AuthCraftConfig getConfig() { return config; }
    public PlatformAdapter getPlatform() { return platform; }
    public StorageProvider getStorage() { return storage; }
    public AuthService getAuthService() { return authService; }
    public SessionService getSessionService() { return sessionService; }
    public PasswordValidator getPasswordValidator() { return passwordValidator; }
    public RoleService getRoleService() { return roleService; }
    public AuditService getAuditService() { return auditService; }
    public TwoFactorService getTwoFactorService() { return twoFactorService; }
    public MessageService getMessageService() { return messageService; }
    public BackupService getBackupService() { return backupService; }
    public HashingStrategy getPrimaryHasher() { return primaryHasher; }
    public Map<TwoFactorMethod, TwoFactorProvider> getTwoFactorProviders() { return twoFactorProviders; }
    public TwoFactorProvider getTwoFactorProvider(TwoFactorMethod method) { return twoFactorProviders.get(method); }
    public Set<UUID> getAuthenticatedPlayers() { return Collections.unmodifiableSet(authenticatedPlayers); }
    public Set<UUID> getLimboPlayers() { return Collections.unmodifiableSet(limboPlayers); }
}