package com.authcraft.web.websocket;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.Session;
import com.authcraft.core.api.StorageProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.websocket.WsContext;
import io.javalin.websocket.WsMessageContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * WebSocket handler for real-time dashboard updates.
 * Provides live statistics, player monitoring, and security alerts.
 */
public class RealtimeHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(RealtimeHandler.class);
    
    private final AuthCraftCore core;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    // Active WebSocket connections
    private final Set<WsContext> connections = new CopyOnWriteArraySet<>();
    
    // Last known stats for change detection
    private volatile int lastOnlineCount = 0;
    private volatile int lastActiveThreats = 0;
    
    public RealtimeHandler(AuthCraftCore core) {
        this.core = core;
    }
    
    /**
     * Handle new WebSocket connection.
     */
    public void onConnect(WsContext ctx) {
        connections.add(ctx);
        logger.debug("WebSocket connected: {} (total: {})", ctx.getSessionId(), connections.size());
        
        // Send initial data
        try {
            sendInitialData(ctx);
        } catch (Exception e) {
            logger.error("Error sending initial data", e);
        }
    }
    
    /**
     * Handle WebSocket disconnection.
     */
    public void onClose(WsContext ctx) {
        connections.remove(ctx);
        logger.debug("WebSocket disconnected: {} (total: {})", ctx.getSessionId(), connections.size());
    }
    
    /**
     * Handle WebSocket message.
     */
    public void onMessage(WsMessageContext ctx) {
        String message = ctx.message();
        logger.debug("WebSocket message: {}", message);
        
        try {
            Map<String, Object> request = objectMapper.readValue(message, Map.class);
            String action = (String) request.get("action");
            
            switch (action) {
                case "ping" -> ctx.send(createMessage("pong", Map.of("timestamp", System.currentTimeMillis())));
                case "subscribe" -> handleSubscribe(ctx, request);
                case "unsubscribe" -> handleUnsubscribe(ctx, request);
                default -> ctx.send(createMessage("error", Map.of("message", "Unknown action")));
            }
        } catch (Exception e) {
            logger.error("Error handling message", e);
        }
    }
    
    /**
     * Handle WebSocket error.
     */
    public void onError(WsContext ctx) {
        logger.error("WebSocket error: {}", ctx.getSessionId());
        connections.remove(ctx);
    }
    
    /**
     * Send initial data to newly connected client.
     */
    private void sendInitialData(WsContext ctx) {
        // Send current stats
        broadcastStats();
    }
    
    /**
     * Handle subscription request.
     */
    @SuppressWarnings("unchecked")
    private void handleSubscribe(WsContext ctx, Map<String, Object> request) {
        String channel = (String) request.get("channel");
        ctx.attribute("subscribed_" + channel, true);
        ctx.send(createMessage("subscribed", Map.of("channel", channel)));
    }
    
    /**
     * Handle unsubscription request.
     */
    @SuppressWarnings("unchecked")
    private void handleUnsubscribe(WsContext ctx, Map<String, Object> request) {
        String channel = (String) request.get("channel");
        ctx.attribute("subscribed_" + channel, null);
        ctx.send(createMessage("unsubscribed", Map.of("channel", channel)));
    }
    
    /**
     * Broadcast stats to all connected clients.
     */
    public void broadcastStats() {
        if (connections.isEmpty()) {
            return;
        }
        
        try {
            StorageProvider storage = core.getStorage();
            
            // Get current stats
            int onlineCount = core.getAuthenticatedPlayers().size();
            long totalAccounts = storage.countAllAccounts().join();
            long activeSessions = storage.countActiveSessions().join();
            
            Map<String, Object> stats = Map.of(
                "onlinePlayers", onlineCount,
                "totalAccounts", totalAccounts,
                "activeSessions", activeSessions,
                "timestamp", System.currentTimeMillis()
            );
            
            String message = createMessage("stats", stats);
            
            for (WsContext ctx : connections) {
                try {
                    ctx.send(message);
                } catch (Exception e) {
                    logger.debug("Error sending to client: {}", e.getMessage());
                }
            }
            
            lastOnlineCount = onlineCount;
            
        } catch (Exception e) {
            logger.error("Error broadcasting stats", e);
        }
    }
    
    /**
     * Check for and broadcast security alerts.
     */
    public void checkSecurityAlerts() {
        if (connections.isEmpty()) {
            return;
        }
        
        try {
            // Check for recent security events
            StorageProvider storage = core.getStorage();
            long recentEvents = storage.countRecentSecurityEvents(60).join(); // Last minute
            
            if (recentEvents > 0) {
                Map<String, Object> alert = Map.of(
                    "type", "security_activity",
                    "count", recentEvents,
                    "timestamp", System.currentTimeMillis()
                );
                
                broadcast("security", alert);
            }
            
        } catch (Exception e) {
            logger.error("Error checking security alerts", e);
        }
    }
    
    /**
     * Broadcast a security event to all subscribed clients.
     */
    public void broadcastSecurityEvent(AuditEvent event) {
        Map<String, Object> data = Map.of(
            "type", event.getEventType().name(),
            "player", event.getPlayerUuid() != null ? event.getPlayerUuid().toString() : null,
            "ip", event.getIpAddress(),
            "details", event.getDetails() != null ? event.getDetails() : "",
            "timestamp", event.getTimestamp()
        );
        
        broadcast("security", data);
    }
    
    /**
     * Broadcast player join event.
     */
    public void broadcastPlayerJoin(String username, java.util.UUID uuid) {
        Map<String, Object> data = Map.of(
            "username", username,
            "uuid", uuid.toString(),
            "timestamp", System.currentTimeMillis()
        );
        
        broadcast("players", Map.of("action", "join", "data", data));
    }
    
    /**
     * Broadcast player leave event.
     */
    public void broadcastPlayerLeave(String username, java.util.UUID uuid) {
        Map<String, Object> data = Map.of(
            "username", username,
            "uuid", uuid.toString(),
            "timestamp", System.currentTimeMillis()
        );
        
        broadcast("players", Map.of("action", "leave", "data", data));
    }
    
    /**
     * Broadcast message to all clients subscribed to a channel.
     */
    private void broadcast(String channel, Map<String, Object> data) {
        String message = createMessage(channel, data);
        
        for (WsContext ctx : connections) {
            try {
                Boolean subscribed = ctx.attribute("subscribed_" + channel);
                if (subscribed != null && subscribed) {
                    ctx.send(message);
                }
            } catch (Exception e) {
                logger.debug("Error broadcasting to client: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Create a JSON message string.
     */
    private String createMessage(String type, Map<String, Object> data) {
        try {
            Map<String, Object> message = new java.util.HashMap<>();
            message.put("type", type);
            message.put("data", data);
            message.put("timestamp", System.currentTimeMillis());
            return objectMapper.writeValueAsString(message);
        } catch (Exception e) {
            return "{\"type\":\"error\",\"data\":{\"message\":\"Failed to serialize message\"}}";
        }
    }
    
    /**
     * Shutdown the handler.
     */
    public void shutdown() {
        for (WsContext ctx : connections) {
            try {
                ctx.closeSession();
            } catch (Exception e) {
                // Ignore
            }
        }
        connections.clear();
    }
}
