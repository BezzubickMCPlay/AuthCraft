package com.authcraft.bukkit;

import com.authcraft.bukkit.adapter.BukkitPlatformAdapter;
import com.authcraft.bukkit.command.*;
import com.authcraft.bukkit.config.BukkitConfigLoader;
import com.authcraft.bukkit.integration.PlaceholderAPIIntegration;
import com.authcraft.bukkit.integration.VaultIntegration;
import com.authcraft.bukkit.listener.*;
import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.crypto.TOTPProvider;
import com.authcraft.integrations.telegram.TelegramBotPoller;
import com.authcraft.integrations.telegram.TelegramProvider;
import com.authcraft.integrations.vk.VKBotPoller;
import com.authcraft.integrations.vk.VKProvider;
import com.authcraft.security.*;
import com.authcraft.storage.StorageFactory;

import org.bukkit.plugin.java.JavaPlugin;

import java.util.ArrayList;
import java.util.List;

public class AuthCraftPlugin extends JavaPlugin {

    private AuthCraftCore core;
    private SecurityChain securityChain;
    private TelegramBotPoller telegramPoller;
    private VKBotPoller vkPoller;

    @Override
    public void onEnable() {
        long start = System.currentTimeMillis();
        saveDefaultConfig();
        AuthCraftConfig config = BukkitConfigLoader.load(getConfig());
        BukkitPlatformAdapter adapter = new BukkitPlatformAdapter(this);
        var storage = StorageFactory.create(config, getLogger(), getDataFolder());

        // 2FA providers
        List<TwoFactorProvider> providers = new ArrayList<>();
        TelegramProvider telegramProvider = null;
        VKProvider vkProvider = null;

        if (config.isTotpEnabled()) providers.add(new TOTPProvider());

        if (config.isTelegramEnabled() && !config.getTelegramBotToken().isEmpty()) {
            telegramProvider = new TelegramProvider(config.getTelegramBotToken(),
                    getConfig().getString("2fa.telegram.bot-username", "AuthCraftBot"));
            providers.add(telegramProvider);
        }

        if (config.isVkEnabled() && !config.getVkBotToken().isEmpty()) {
            vkProvider = new VKProvider(config.getVkBotToken());
            providers.add(vkProvider);
        }

        // Core
        core = new AuthCraftCore(config, adapter, storage, providers);

        // Security
        AntiBot antiBot = new AntiBot(config, getLogger());
        GeoIPFilter geoIP = new GeoIPFilter(config, getLogger(), getDataFolder());
        UnicodeSpoofDetector spoofDetector = new UnicodeSpoofDetector(config, getLogger());
        securityChain = new SecurityChain(config, antiBot, geoIP, spoofDetector, core.getAuditService(), getLogger());

        core.enable();

        // Load usernames for spoof detection
        storage.getAllAccounts().thenAccept(accounts -> {
            for (var acc : accounts) securityChain.registerUsername(acc.getUsername());
            getLogger().info("[AuthCraft] Loaded " + accounts.size() + " usernames");
        });

        // Listeners
        var pm = getServer().getPluginManager();
        pm.registerEvents(new PlayerJoinListener(core, securityChain), this);
        pm.registerEvents(new PlayerQuitListener(core), this);
        pm.registerEvents(new LimboListener(core, config), this);
        pm.registerEvents(new ChatListener(core), this);

        // Commands
        getCommand("register").setExecutor(new RegisterCommand(core));
        getCommand("login").setExecutor(new LoginCommand(core));
        getCommand("changepassword").setExecutor(new ChangePasswordCommand(core));
        getCommand("logout").setExecutor(new LogoutCommand(core));
        getCommand("2fa").setExecutor(new TwoFactorCommand(core));
        getCommand("authcraft").setExecutor(new AuthCraftAdminCommand(core, securityChain));

        // Telegram polling
        if (telegramProvider != null && telegramProvider.isAvailable()) {
            telegramPoller = new TelegramBotPoller(telegramProvider.getBot(), telegramProvider,
                core, core.getAuthService().getConfirmationService(), getLogger());
            telegramPoller.startPolling();
        }

        // VK polling
        if (vkProvider != null && vkProvider.isAvailable()) {
            vkPoller = new VKBotPoller(vkProvider, core,
                core.getAuthService().getConfirmationService(), getLogger());
            vkPoller.startPolling();
        }

        // Security Audit
        if (config.isSecurityAuditOnStartup()) {
            getServer().getScheduler().runTaskAsynchronously(this, () -> {
                new SecurityAudit(config, core.getAuditService(), getLogger(),
                        getServer().getWorldContainer()).runAudit();
            });
        }

        // Periodic cleanup
        getServer().getScheduler().runTaskTimerAsynchronously(this, antiBot::cleanup, 6000L, 6000L);
        getServer().getScheduler().runTaskTimerAsynchronously(this,
                () -> core.getAuthService().getConfirmationService().cleanupExpired(), 600L, 600L);

        // Vault integration
        if (pm.getPlugin("Vault") != null) {
            new VaultIntegration(getLogger());
        }

        // PlaceholderAPI integration
        if (pm.getPlugin("PlaceholderAPI") != null) {
            new PlaceholderAPIIntegration(core).register();
            getLogger().info("[AuthCraft] PlaceholderAPI integration registered");
        }

        getLogger().info("[AuthCraft] Enabled in " + (System.currentTimeMillis() - start) + "ms");
    }

    @Override
    public void onDisable() {
        if (telegramPoller != null) telegramPoller.stopPolling();
        if (vkPoller != null) vkPoller.stopPolling();
        if (core != null) core.disable();
    }

    public AuthCraftCore getCore() { return core; }
}