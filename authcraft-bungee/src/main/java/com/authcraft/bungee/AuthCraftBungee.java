// com/authcraft/bungee/AuthCraftBungee.java
package com.authcraft.bungee;

import com.authcraft.bungee.adapter.BungeePlatformAdapter;
import com.authcraft.bungee.listener.BungeePlayerListener;
import com.authcraft.bungee.listener.BungeeChatListener;
import com.authcraft.bungee.command.*;
import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.crypto.TOTPProvider;
import com.authcraft.security.*;
import com.authcraft.storage.StorageFactory;

import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class AuthCraftBungee extends Plugin {

    private AuthCraftCore core;
    private SecurityChain securityChain;

    @Override
    public void onEnable() {
        long startTime = System.currentTimeMillis();

        // 1. Config
        saveDefaultConfig();
        AuthCraftConfig config = loadConfig();

        // 2. Adapter
        BungeePlatformAdapter adapter = new BungeePlatformAdapter(this);

        // 3. Storage
        var storage = StorageFactory.create(
                config, getLogger(), getDataFolder()
        );

        // 4. 2FA Providers
        List<TwoFactorProvider> providers = new ArrayList<>();
        if (config.isTotpEnabled()) {
            providers.add(new TOTPProvider());
        }

        // 5. Core
        core = new AuthCraftCore(config, adapter, storage, providers);

        // 6. Security
        AntiBot antiBot = new AntiBot(config, getLogger());
        GeoIPFilter geoIP = new GeoIPFilter(config, getLogger(), getDataFolder());
        UnicodeSpoofDetector spoofDetector = new UnicodeSpoofDetector(config, getLogger());

        securityChain = new SecurityChain(
                config, antiBot, geoIP, spoofDetector,
                core.getAuditService(), getLogger()
        );

        // 7. Enable
        core.enable();

        // 8. Load usernames
        storage.getAllAccounts().thenAccept(accounts -> {
            for (var acc : accounts) {
                securityChain.registerUsername(acc.getUsername());
            }
            getLogger().info("[AuthCraft] Loaded " + accounts.size()
                    + " usernames for spoof detection");
        });

        // 9. Listeners
        getProxy().getPluginManager().registerListener(this,
                new BungeePlayerListener(core, securityChain));
        getProxy().getPluginManager().registerListener(this,
                new BungeeChatListener(core));

        // 10. Commands
        getProxy().getPluginManager().registerCommand(this,
                new BungeeRegisterCommand(core));
        getProxy().getPluginManager().registerCommand(this,
                new BungeeLoginCommand(core));
        getProxy().getPluginManager().registerCommand(this,
                new BungeeChangePasswordCommand(core));
        getProxy().getPluginManager().registerCommand(this,
                new BungeeTwoFactorCommand(core));
        getProxy().getPluginManager().registerCommand(this,
                new BungeeAdminCommand(core, securityChain));

        // 11. Security Audit
        if (config.isSecurityAuditOnStartup()) {
            getProxy().getScheduler().runAsync(this, () -> {
                SecurityAudit audit = new SecurityAudit(
                        config, core.getAuditService(), getLogger(),
                        getProxy().getPluginsFolder().getParentFile()
                );
                audit.runAudit();
            });
        }

        long elapsed = System.currentTimeMillis() - startTime;
        getLogger().info("[AuthCraft-Bungee] Enabled in " + elapsed + "ms");
    }

    @Override
    public void onDisable() {
        if (core != null) {
            core.disable();
        }
        getLogger().info("[AuthCraft-Bungee] Disabled");
    }

    private void saveDefaultConfig() {
        if (!getDataFolder().exists()) {
            getDataFolder().mkdirs();
        }
        File configFile = new File(getDataFolder(), "config.yml");
        if (!configFile.exists()) {
            try (InputStream in = getResourceAsStream("bungee-config.yml")) {
                if (in != null) {
                    try (OutputStream out = new FileOutputStream(configFile)) {
                        in.transferTo(out);
                    }
                }
            } catch (IOException e) {
                getLogger().warning("Could not save default config: " + e.getMessage());
            }
        }
    }

    private AuthCraftConfig loadConfig() {
        AuthCraftConfig config = new AuthCraftConfig();
        try {
            File configFile = new File(getDataFolder(), "config.yml");
            Configuration yml = ConfigurationProvider
                    .getProvider(YamlConfiguration.class)
                    .load(configFile);

            config.setDatabaseType(yml.getString("database.type", "sqlite"));
            config.setDatabaseHost(yml.getString("database.host", "localhost"));
            config.setDatabasePort(yml.getInt("database.port", 3306));
            config.setDatabaseName(yml.getString("database.name", "authcraft"));
            config.setDatabaseUsername(yml.getString("database.username", "root"));
            config.setDatabasePassword(yml.getString("database.password", ""));
            config.setDatabaseFile(yml.getString("database.file", "authcraft.db"));

            config.setHashAlgorithm(com.authcraft.core.model.HashAlgorithm.fromId(
                    yml.getString("security.hash-algorithm", "argon2id")));
            config.setMaxLoginAttempts(yml.getInt("login.max-attempts", 5));
            config.setSessionTtlHours(yml.getLong("session.ttl-hours", 168));
            config.setSessionStrictIp(yml.getBoolean("session.strict-ip", true));

            config.setTotpEnabled(yml.getBoolean("2fa.totp.enabled", true));
            config.setAntiBotEnabled(yml.getBoolean("antibot.enabled", true));
            config.setGeoIpEnabled(yml.getBoolean("geoip.enabled", false));
            config.setUnicodeSpoofingDetection(
                    yml.getBoolean("unicode-spoofing.enabled", true));
            config.setSecurityAuditOnStartup(
                    yml.getBoolean("security-audit.enabled", true));
            config.setDefaultLanguage(yml.getString("language", "ru"));

        } catch (IOException e) {
            getLogger().warning("Could not load config: " + e.getMessage());
        }
        return config;
    }

    public AuthCraftCore getCore() { return core; }
}