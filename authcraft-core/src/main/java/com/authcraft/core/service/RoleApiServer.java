// com/authcraft/core/service/RoleApiServer.java
package com.authcraft.core.service;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.AuditEventType;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.logging.Logger;

/**
 * Lightweight REST API for external role assignment.
 * Used by donation websites to assign roles via POST.
 *
 * POST /api/setrole
 * Headers: Authorization: Bearer <api-key>
 * Body: {"username": "Player", "role": "donator"}
 */
public class RoleApiServer {

    private final AuthCraftCore core;
    private final AuthCraftConfig config;
    private final Logger logger;
    private final Gson gson;
    private HttpServer httpServer;

    // Config
    private final String apiKey;
    private final Set<String> allowedIps;
    private final int port;
    private final boolean enabled;

    public RoleApiServer(AuthCraftCore core, String apiKey,
                         Set<String> allowedIps, int port,
                         boolean enabled) {
        this.core = core;
        this.config = core.getConfig();
        this.logger = core.getPlatform().getLogger();
        this.gson = new Gson();
        this.apiKey = apiKey;
        this.allowedIps = allowedIps;
        this.port = port;
        this.enabled = enabled;
    }

    public void start() {
        if (!enabled || apiKey == null || apiKey.isEmpty()) {
            logger.info("[AuthCraft] REST API disabled.");
            return;
        }

        try {
            httpServer = HttpServer.create(
                    new InetSocketAddress("127.0.0.1", port), 0
            );

            httpServer.createContext("/api/setrole",
                    new SetRoleHandler());
            httpServer.createContext("/api/info",
                    new PlayerInfoHandler());
            httpServer.createContext("/api/health",
                    exchange -> respond(exchange, 200, "{\"status\":\"ok\"}"));

            httpServer.setExecutor(java.util.concurrent.Executors
                    .newFixedThreadPool(2));
            httpServer.start();

            logger.info("[AuthCraft] REST API started on port " + port);

        } catch (IOException e) {
            logger.severe("[AuthCraft] Failed to start REST API: "
                    + e.getMessage());
        }
    }

    public void stop() {
        if (httpServer != null) {
            httpServer.stop(1);
            logger.info("[AuthCraft] REST API stopped.");
        }
    }

    /**
     * Verify API key using constant-time comparison.
     */
    private boolean verifyApiKey(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders()
                .getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }

        String providedKey = authHeader.substring(7);
        return MessageDigest.isEqual(
                providedKey.getBytes(StandardCharsets.UTF_8),
                apiKey.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Verify source IP.
     */
    private boolean verifyIp(HttpExchange exchange) {
        if (allowedIps.isEmpty()) return true; // No restrictions
        String remoteIp = exchange.getRemoteAddress()
                .getAddress().getHostAddress();
        return allowedIps.contains(remoteIp)
                || remoteIp.equals("127.0.0.1")
                || remoteIp.equals("0:0:0:0:0:0:0:1");
    }

    private void respond(HttpExchange exchange, int code,
                         String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=utf-8");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private String readBody(HttpExchange exchange) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    // ==========================================
    // Handlers
    // ==========================================

    private class SetRoleHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                respond(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            if (!verifyIp(exchange)) {
                respond(exchange, 403,
                        "{\"error\":\"IP not allowed\"}");
                logger.warning("[AuthCraft API] Blocked request from "
                        + exchange.getRemoteAddress());
                return;
            }

            if (!verifyApiKey(exchange)) {
                respond(exchange, 401,
                        "{\"error\":\"Invalid API key\"}");
                return;
            }

            String body = readBody(exchange);
            JsonObject json = gson.fromJson(body, JsonObject.class);

            String username = json.has("username")
                    ? json.get("username").getAsString() : null;
            String role = json.has("role")
                    ? json.get("role").getAsString() : null;

            if (username == null || role == null) {
                respond(exchange, 400,
                        "{\"error\":\"Missing username or role\"}");
                return;
            }

            if (!core.getRoleService().isValidRole(role)) {
                respond(exchange, 400,
                        "{\"error\":\"Invalid role: " + role + "\"}");
                return;
            }

            core.getAuthService().setRole(null, username, role)
                    .thenAccept(success -> {
                        try {
                            if (success) {
                                core.getAuditService().log(
                                        AuditEventType.ROLE_CHANGED,
                                        null, username,
                                        exchange.getRemoteAddress()
                                                .getAddress().getHostAddress(),
                                        "API: role set to " + role
                                );
                                respond(exchange, 200,
                                        "{\"success\":true,\"message\":"
                                                + "\"Role set to " + role + "\"}");
                            } else {
                                respond(exchange, 404,
                                        "{\"error\":\"Player not found\"}");
                            }
                        } catch (IOException e) {
                            logger.warning("[AuthCraft API] Error: "
                                    + e.getMessage());
                        }
                    });
        }
    }

    private class PlayerInfoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                respond(exchange, 405,
                        "{\"error\":\"Method not allowed\"}");
                return;
            }

            if (!verifyIp(exchange) || !verifyApiKey(exchange)) {
                respond(exchange, 403,
                        "{\"error\":\"Forbidden\"}");
                return;
            }

            String query = exchange.getRequestURI().getQuery();
            if (query == null || !query.startsWith("username=")) {
                respond(exchange, 400,
                        "{\"error\":\"Missing username param\"}");
                return;
            }

            String username = query.substring(9);
            core.getStorage().getAccountByName(username)
                    .thenAccept(opt -> {
                        try {
                            if (opt.isEmpty()) {
                                respond(exchange, 404,
                                        "{\"error\":\"Not found\"}");
                                return;
                            }
                            var acc = opt.get();
                            JsonObject result = new JsonObject();
                            result.addProperty("uuid",
                                    acc.getUuid().toString());
                            result.addProperty("username",
                                    acc.getUsername());
                            result.addProperty("role", acc.getRole());
                            result.addProperty("status",
                                    acc.getStatus().name());
                            result.addProperty("2fa",
                                    acc.getTwoFactorMethod().name());
                            result.addProperty("registered",
                                    acc.getCreatedAt().toString());
                            respond(exchange, 200, gson.toJson(result));
                        } catch (IOException e) {
                            logger.warning("[AuthCraft API] Error: "
                                    + e.getMessage());
                        }
                    });
        }
    }
}