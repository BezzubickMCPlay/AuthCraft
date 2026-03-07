package com.authcraft.web;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.web.api.*;
import com.authcraft.web.auth.AuthManager;
import com.authcraft.web.auth.JwtManager;
import com.authcraft.web.websocket.RealtimeHandler;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Main web dashboard server for AuthCraft.
 * Provides a web-based admin panel for server management, real-time monitoring,
 * 2FA statistics, security event visualization, and configuration management.
 */
public class WebDashboardServer {
    
    private static final Logger logger = LoggerFactory.getLogger(WebDashboardServer.class);
    
    private final AuthCraftCore core;
    private final AuthCraftConfig config;
    private final int port;
    private final String host;
    
    private Javalin app;
    private JwtManager jwtManager;
    private AuthManager authManager;
    private RealtimeHandler realtimeHandler;
    private ScheduledExecutorService scheduler;
    
    private boolean running = false;
    
    public WebDashboardServer(AuthCraftCore core, AuthCraftConfig config) {
        this.core = core;
        this.config = config;
        this.port = config.getWebDashboardPort();
        this.host = config.getWebDashboardHost();
    }
    
    /**
     * Start the web dashboard server.
     */
    public void start() {
        if (running) {
            logger.warn("Web dashboard is already running");
            return;
        }
        
        try {
            // Initialize components
            jwtManager = new JwtManager(config.getWebDashboardSecret());
            authManager = new AuthManager(core, jwtManager);
            realtimeHandler = new RealtimeHandler(core);
            scheduler = Executors.newScheduledThreadPool(2);
            
            // Create Javalin app
            app = Javalin.create(javalinConfig -> {
                // Serve static files from resources
                javalinConfig.staticFiles.add("/web", Location.CLASSPATH);
    
                // Enable CORS for all origins
                javalinConfig.plugins.enableCors(cors -> {
                    cors.add(corsConfig -> {
                        corsConfig.anyHost();
                    });
                });
            });
            
            // Configure routes
            configureRoutes();
            
            // Start server
            app.start(host, port);
            
            // Start background tasks
            startBackgroundTasks();
            
            running = true;
            logger.info("Web dashboard started on http://{}:{}", host, port);
            
        } catch (Exception e) {
            logger.error("Failed to start web dashboard", e);
        }
    }
    
    /**
     * Stop the web dashboard server.
     */
    public void stop() {
        if (!running) {
            return;
        }
        
        try {
            if (scheduler != null) {
                scheduler.shutdown();
                scheduler.awaitTermination(5, TimeUnit.SECONDS);
            }
            
            if (realtimeHandler != null) {
                realtimeHandler.shutdown();
            }
            
            if (app != null) {
                app.stop();
            }
            
            running = false;
            logger.info("Web dashboard stopped");
            
        } catch (Exception e) {
            logger.error("Error stopping web dashboard", e);
        }
    }
    
    /**
     * Configure all API routes.
     */
    private void configureRoutes() {
        // Authentication routes
        app.post("/api/auth/login", authManager::handleLogin);
        app.post("/api/auth/logout", authManager::handleLogout);
        app.get("/api/auth/verify", authManager::handleVerify);
        app.post("/api/auth/refresh", authManager::handleRefresh);
        
        // Protected routes (require authentication)
        app.before("/api/*", ctx -> {
            if (!ctx.path().equals("/api/auth/login") && 
                !ctx.path().equals("/api/auth/verify")) {
                authManager.requireAuth(ctx);
            }
        });
        
        // Dashboard API
        DashboardApi dashboardApi = new DashboardApi(core);
        app.get("/api/dashboard/stats", dashboardApi::getStats);
        app.get("/api/dashboard/online", dashboardApi::getOnlinePlayers);
        app.get("/api/dashboard/activity", dashboardApi::getActivity);
        
        // Players API
        PlayersApi playersApi = new PlayersApi(core);
        app.get("/api/players", playersApi::listPlayers);
        app.get("/api/players/{uuid}", playersApi::getPlayer);
        app.put("/api/players/{uuid}", playersApi::updatePlayer);
        app.delete("/api/players/{uuid}", playersApi::deletePlayer);
        app.post("/api/players/{uuid}/unlock", playersApi::unlockPlayer);
        app.post("/api/players/{uuid}/reset-2fa", playersApi::reset2FA);
        
        // Security API
        SecurityApi securityApi = new SecurityApi(core);
        app.get("/api/security/events", securityApi::getSecurityEvents);
        app.get("/api/security/threats", securityApi::getActiveThreats);
        app.get("/api/security/blocked-ips", securityApi::getBlockedIps);
        app.delete("/api/security/blocked-ips/{ip}", securityApi::unblockIp);
        app.get("/api/security/audit-log", securityApi::getAuditLog);
        
        // 2FA Statistics API
        TwoFactorApi twoFactorApi = new TwoFactorApi(core);
        app.get("/api/2fa/stats", twoFactorApi::getStats);
        app.get("/api/2fa/methods", twoFactorApi::getMethodDistribution);
        app.get("/api/2fa/adoption", twoFactorApi::getAdoptionRate);
        
        // Configuration API
        ConfigurationApi configApi = new ConfigurationApi(core, config);
        app.get("/api/config", configApi::getConfig);
        app.put("/api/config", configApi::updateConfig);
        app.post("/api/config/reload", configApi::reloadConfig);
        app.get("/api/config/schema", configApi::getConfigSchema);
        
        // WebSocket for real-time updates
        app.ws("/ws", wsHandler -> {
            wsHandler.onConnect(realtimeHandler::onConnect);
            wsHandler.onClose(realtimeHandler::onClose);
            wsHandler.onMessage(realtimeHandler::onMessage);
            wsHandler.onError(realtimeHandler::onError);
        });
        
        // Error handling
        app.exception(Exception.class, (e, ctx) -> {
            logger.error("Unhandled exception", e);
            ctx.status(500).json(new ApiResponse(false, "Internal server error"));
        });
    }
    
    /**
     * Start background tasks for real-time updates.
     */
    private void startBackgroundTasks() {
        // Push real-time stats every 5 seconds
        scheduler.scheduleAtFixedRate(() -> {
            if (running && realtimeHandler != null) {
                realtimeHandler.broadcastStats();
            }
        }, 5, 5, TimeUnit.SECONDS);
        
        // Push security alerts immediately
        scheduler.scheduleAtFixedRate(() -> {
            if (running && realtimeHandler != null) {
                realtimeHandler.checkSecurityAlerts();
            }
        }, 1, 1, TimeUnit.SECONDS);
    }
    
    public boolean isRunning() {
        return running;
    }
    
    public int getPort() {
        return port;
    }
    
    public String getHost() {
        return host;
    }
}
