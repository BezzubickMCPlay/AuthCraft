// com/authcraft/velocity/AuthCraftVelocity.java
package com.authcraft.velocity;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.crypto.TOTPProvider;
import com.authcraft.security.*;
import com.authcraft.storage.StorageFactory;
import com.authcraft.velocity.adapter.VelocityPlatformAdapter;
import com.authcraft.velocity.listener.VelocityPlayerListener;
import com.authcraft.velocity.command.VelocityCommandRegistrar;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;

import java.io.*;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@Plugin(
        id = "authcraft",
        name = "AuthCraft",
        version = "1.0.0-BETA",
        description = "Advanced authentication for Velocity",
        authors = {"AuthCraft Team"}
)
public class AuthCraftVelocity {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private AuthCraftCore core;
    private SecurityChain securityChain;

    @Inject
    public AuthCraftVelocity(ProxyServer server, Logger logger,
                             @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        long startTime = System.currentTimeMillis();

        File dataFolder = dataDirectory.toFile();
        if (!dataFolder.exists()) dataFolder.mkdirs();

        // Config
        AuthCraftConfig config = new AuthCraftConfig();
        config.setDatabaseType("sqlite");
        config.setDatabaseFile("authcraft.db");
        // Load from file in production

        // Adapter
        VelocityPlatformAdapter adapter = new VelocityPlatformAdapter(
                server, logger, dataFolder, this
        );

        // Storage
        var storage = StorageFactory.create(config, logger, dataFolder);

        // 2FA
        List<TwoFactorProvider> providers = new ArrayList<>();
        if (config.isTotpEnabled()) providers.add(new TOTPProvider());

        // Core
        core = new AuthCraftCore(config, adapter, storage, providers);

        // Security
        AntiBot antiBot = new AntiBot(config, logger);
        GeoIPFilter geoIP = new GeoIPFilter(config, logger, dataFolder);
        UnicodeSpoofDetector spoofDetector = new UnicodeSpoofDetector(config, logger);

        securityChain = new SecurityChain(
                config, antiBot, geoIP, spoofDetector,
                core.getAuditService(), logger
        );

        core.enable();

        // Load usernames
        storage.getAllAccounts().thenAccept(accounts -> {
            for (var acc : accounts) securityChain.registerUsername(acc.getUsername());
            logger.info("[AuthCraft] Loaded " + accounts.size() + " usernames");
        });

        // Listeners
        server.getEventManager().register(this,
                new VelocityPlayerListener(core, securityChain));

        // Commands
        VelocityCommandRegistrar.registerAll(server, core, securityChain);

        long elapsed = System.currentTimeMillis() - startTime;
        logger.info("[AuthCraft-Velocity] Enabled in " + elapsed + "ms");
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (core != null) core.disable();
        logger.info("[AuthCraft-Velocity] Disabled");
    }
}