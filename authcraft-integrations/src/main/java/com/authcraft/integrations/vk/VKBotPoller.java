// com/authcraft/integrations/vk/VKBotPoller.java
package com.authcraft.integrations.vk;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.LoginConfirmation;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.core.service.LoginConfirmationService;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Polls VK LongPoll API for incoming messages and handles:
 * - Link code verification (when user sends 6-digit code)
 * - Button callbacks (approve/deny login requests)
 */
public class VKBotPoller {

    private final VKProvider provider;
    private final AuthCraftCore core;
    private final AuthCraftConfig config;
    private final LoginConfirmationService confirmationService;
    private final Logger logger;
    private final String botToken;
    private final Gson gson = new Gson();

    private ScheduledExecutorService executor;
    private volatile boolean running = false;

    // LongPoll state
    private String longPollServer;
    private String longPollKey;
    private String longPollTs;

    // Group ID for Bots LongPoll API
    private Integer groupId;

    private static final String VK_API = "https://api.vk.com/method/";
    private static final String API_VERSION = "5.199";

    public VKBotPoller(VKProvider provider, AuthCraftCore core,
                       LoginConfirmationService confirmationService, Logger logger) {
        this.provider = provider;
        this.core = core;
        this.config = core.getConfig();
        this.confirmationService = confirmationService;
        this.logger = logger;
        this.botToken = provider.getBotToken();
    }

    /**
     * Check if debug mode is enabled for integrations
     */
    private boolean isDebug() {
        return config != null && config.isDebugIntegrations();
    }

    /**
     * Debug log - only shown when debug mode is enabled
     */
    private void debug(String message) {
        if (isDebug()) {
            logger.info("[AuthCraft VK DEBUG] " + message);
        }
    }

    /**
     * Debug log with user interaction - always shown in debug mode
     */
    private void debugUserAction(int userId, String action, String details) {
        if (isDebug()) {
            logger.info("[AuthCraft VK] User " + userId + " -> " + action + ": " + details);
        }
    }

    public void startPolling() {
        if (running) return;
        running = true;

        debug("Starting VK polling initialization...");
        debug("Bot token length: " + (botToken != null ? botToken.length() : "null"));

        // Get initial LongPoll server
        if (!initLongPoll()) {
            logger.severe("[AuthCraft VK] Failed to initialize LongPoll server");
            return;
        }

        executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleWithFixedDelay(this::pollUpdates, 0, 1, TimeUnit.SECONDS);

        logger.info("[AuthCraft] VK bot polling started" + (isDebug() ? " (DEBUG MODE)" : ""));
    }

    public void stopPolling() {
        debug("Stopping VK polling...");
        running = false;
        if (executor != null) {
            executor.shutdown();
            try {
                executor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        debug("VK polling stopped");
    }

    private boolean initLongPoll() {
    	try {
    		debug("Requesting LongPoll server from VK API...");
   
    		// First, get the group ID from the token if we don't have it
    		if (groupId == null) {
    			debug("Getting group ID from token...");
    			String groupIdUrl = VK_API + "groups.getById?"
    				+ "&access_token=" + botToken
    				+ "&v=" + API_VERSION;
    			JsonObject groupIdResponse = executeVkRequest(groupIdUrl);
    			if (groupIdResponse != null && groupIdResponse.has("response")) {
    				JsonArray groups = groupIdResponse.getAsJsonObject("response").getAsJsonArray("groups");
    				if (groups.size() > 0) {
    					groupId = groups.get(0).getAsJsonObject().get("id").getAsInt();
    					debug("Group ID: " + groupId);
    				}
    			}
    			if (groupId == null) {
    				debug("ERROR: Could not get group ID from token");
    				return false;
    			}
    		}
   
    		// Use Bots LongPoll API (groups.getLongPollServer)
    		String urlStr = VK_API + "groups.getLongPollServer?"
    			+ "group_id=" + groupId
    			+ "&access_token=" + botToken
    			+ "&v=" + API_VERSION;
   
    		debug("LongPoll request URL: " + urlStr.substring(0, Math.min(urlStr.length(), 100)) + "...");
   
    		JsonObject response = executeVkRequest(urlStr);
    		if (response == null) {
    			debug("ERROR: Null response from LongPoll server request");
    			return false;
    		}
   
    		if (!response.has("response")) {
    			debug("ERROR: No 'response' field in LongPoll response: " + response.toString());
    			return false;
    		}
   
    		JsonObject resp = response.getAsJsonObject("response");
    		longPollServer = resp.get("server").getAsString();
    		longPollKey = resp.get("key").getAsString();
    		longPollTs = resp.get("ts").getAsString();
   
    		debug("LongPoll server obtained: " + longPollServer);
    		debug("LongPoll key: " + longPollKey.substring(0, Math.min(longPollKey.length(), 20)) + "...");
    		debug("LongPoll ts: " + longPollTs);
   
    		logger.info("[AuthCraft VK] Bots LongPoll initialized successfully (group_id: " + groupId + ")");
    		return true;
    	} catch (Exception e) {
    		logger.warning("[AuthCraft VK] Error initializing LongPoll: " + e.getMessage());
    		debug("LongPoll init exception stack trace:");
    		if (isDebug()) {
    			e.printStackTrace();
    		}
    		return false;
    	}
    }

    private void pollUpdates() {
    	if (!running) return;
   
    	try {
    		// Build LongPoll URL
    		// The Bots LongPoll API returns the full server URL (e.g., https://lp.vk.com/...)
    		// so we don't need to prepend "https://"
    		String urlStr;
    		if (longPollServer.startsWith("http://") || longPollServer.startsWith("https://")) {
    			// Full URL provided - use as-is
    			urlStr = longPollServer + "?"
    				+ "act=a_check"
    				+ "&key=" + URLEncoder.encode(longPollKey, StandardCharsets.UTF_8)
    				+ "&ts=" + longPollTs
    				+ "&wait=25";
    		} else {
    			// Hostname only - prepend https://
    			urlStr = "https://" + longPollServer + "?"
    				+ "act=a_check"
    				+ "&key=" + URLEncoder.encode(longPollKey, StandardCharsets.UTF_8)
    				+ "&ts=" + longPollTs
    				+ "&wait=25"
    				+ "&mode=2";
    		}

            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }

                    JsonObject response = gson.fromJson(sb.toString(), JsonObject.class);

                    if (response.has("failed")) {
                        int failed = response.get("failed").getAsInt();
                        debug("LongPoll failed with code: " + failed + ", reinitializing...");
                        // Reinitialize LongPoll
                        initLongPoll();
                        return;
                    }

                    if (response.has("ts")) {
                    	longPollTs = response.get("ts").getAsString();
                    }
                 
                    if (response.has("updates")) {
                    	JsonArray updates = response.getAsJsonArray("updates");
                    	if (updates.size() > 0) {
                    		debug("Received " + updates.size() + " update(s)");
                    	}
                    	for (int i = 0; i < updates.size(); i++) {
                    		JsonObject update = updates.get(i).getAsJsonObject();
                    		handleUpdate(update);
                    	}
                    }
                }
            } else {
                debug("LongPoll HTTP error: " + conn.getResponseCode());
            }
        } catch (Exception e) {
            if (running) {
                debug("Poll error: " + e.getMessage());
                if (isDebug()) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void handleUpdate(JsonObject update) {
    	if (!update.has("type")) {
    		debug("Update without type field");
    		return;
    	}
   
    	String type = update.get("type").getAsString();
    	debug("Processing update type: " + type);
   
    	JsonObject object = update.has("object") ? update.getAsJsonObject("object") : null;
    	if (object == null) {
    		debug("Update without object field");
    		return;
    	}
   
    	// message_new = new message from user
    	if ("message_new".equals(type)) {
    		JsonObject message = object.has("message") ? object.getAsJsonObject("message") : object;
    		
    		int userId = message.has("from_id") ? message.get("from_id").getAsInt() : 0;
    		String text = message.has("text") ? message.get("text").getAsString() : "";
    		
    		debug("Full message update: " + update.toString());
    		debugUserAction(userId, "MESSAGE", text);
    		handleMessage(userId, text);
    	}
   
    	// message_event = button callback (inline button press)
    	if ("message_event".equals(type)) {
    		int userId = object.has("user_id") ? object.get("user_id").getAsInt() : 0;
    		JsonObject payload = object.has("payload") ? object.getAsJsonObject("payload") : null;
    		
    		if (payload != null) {
    			debugUserAction(userId, "CALLBACK", payload.toString());
    			handleCallback(userId, payload);
    		} else {
    			debug("Callback without payload from user " + userId);
    		}
    	}
   
    	// message_reply = message sent by bot (skip to avoid loops)
    	if ("message_reply".equals(type)) {
    		debug("Skipping message_reply (sent by bot)");
    	}
    }

    private void handleMessage(int userId, String text) {
        if (text == null || text.isEmpty()) {
            debug("Empty message from user " + userId);
            return;
        }

        text = text.trim();
        debug("Processing message from user " + userId + ": '" + text + "'");

        // Handle /start
        if (text.startsWith("/start")) {
            debugUserAction(userId, "/START", "Sending welcome message");
            sendMessage(userId,
                    "🔐 AuthCraft 2FA Bot\n\n" +
                    "Отправьте код привязки для подключения аккаунта Minecraft.\n" +
                    "Send your link code to connect your Minecraft account.\n\n" +
                    "После привязки вы будете получать запросы на подтверждение входа.\n" +
                    "Once linked, you'll receive login requests with approve/deny buttons.");
            return;
        }

        // Handle /help
        if (text.startsWith("/help")) {
            debugUserAction(userId, "/HELP", "Sending help message");
            sendMessage(userId,
                    "📋 Команды / Commands:\n\n" +
                    "/start — Приветствие / Welcome\n" +
                    "/status — Статус привязки / Link status\n" +
                    "Отправьте 6-значный код — Привязка аккаунта");
            return;
        }

        // Handle /status
        if (text.startsWith("/status")) {
            debugUserAction(userId, "/STATUS", "Checking link status");
            final int uid = userId;
            core.getStorage().getAllAccounts().thenAccept(accounts -> {
                String userIdStr = String.valueOf(uid);
                var linked = accounts.stream()
                        .filter(a -> userIdStr.equals(a.getVkUserId()))
                        .findFirst();

                if (linked.isPresent()) {
                    debugUserAction(uid, "/STATUS", "Linked to: " + linked.get().getUsername());
                    sendMessage(uid, "✅ Привязан к / Linked to: " + linked.get().getUsername());
                } else {
                    debugUserAction(uid, "/STATUS", "Not linked");
                    sendMessage(uid,
                            "❌ Не привязан / Not linked.\n" +
                            "Используйте /2fa enable vk в Minecraft.\n" +
                            "Use /2fa enable vk in Minecraft.");
                }
            });
            return;
        }

        // Try as link code (6 digits)
        if (text.matches("\\d{6}")) {
            debugUserAction(userId, "LINK_CODE", "Attempting to link with code: " + text);
            final String linkCode = text;
            UUID playerUuid = provider.handleLinkCode(linkCode);
            if (playerUuid != null) {
                debugUserAction(userId, "LINK_CODE", "Valid code! Player UUID: " + playerUuid);
                final int uid = userId;
                core.getStorage().getAccount(playerUuid).thenAccept(opt -> {
                    if (opt.isPresent()) {
                        var account = opt.get();
                        account.setVkUserId(String.valueOf(uid));
                        account.enableTwoFactorMethod(TwoFactorMethod.VK);
                        // Note: We don't use setTwoFactorSecretForMethod for VK because
                        // it would overwrite vkUserId. The VK user ID IS the identifier.
                        core.getStorage().saveAccount(account).thenRun(() -> {

                            debugUserAction(uid, "LINK_SUCCESS", "Account linked: " + account.getUsername());
                            sendMessage(uid,
                                    "✅ Аккаунт привязан! / Account linked!\n\n" +
                                    "👤 Игрок / Player: " + account.getUsername() + "\n\n" +
                                    "✅ Двухфакторная аутентификация включена!\n" +
                                    "✅ Two-factor authentication enabled!\n\n" +
                                    "Теперь при входе вы будете получать запрос с кнопками подтверждения.\n" +
                                    "You will now receive login requests with approve/deny buttons.");

                            // Notify player
                            core.getPlatform().sendMessage(playerUuid,
                                    core.getMessageService().get("2fa.enabled"));

                            core.getAuditService().log(
                                    AuditEventType.TWO_FACTOR_ENABLE,
                                    playerUuid, account.getUsername(),
                                    "vk:" + uid, "VK linked"
                            );
                }).exceptionally(ex -> {
                    debugUserAction(uid, "LINK_ERROR", "Failed to save account: " + ex.getMessage());
                    sendMessage(uid, "❌ Ошибка сохранения. Попробуйте снова. / Save error. Please try again.");
                    return null;
                });
                    } else {
                        debugUserAction(uid, "LINK_ERROR", "Account not found for UUID");
                    }
                });
            } else {
                debugUserAction(userId, "LINK_ERROR", "Invalid or expired code");
                sendMessage(userId,
                        "❌ Неверный или истёкший код. / Invalid or expired code.\n" +
                        "Используйте /2fa enable vk в Minecraft.\n" +
                        "Use /2fa enable vk in Minecraft.");
            }
        } else {
            debugUserAction(userId, "UNKNOWN", "Unrecognized message format: " + text);
            // Send helpful response for unrecognized messages
            sendMessage(userId,
                "❓ Неизвестная команда / Unknown command\\n\\n" +
                "📋 Команды / Commands:\\n" +
                "/start — Приветствие / Welcome\\n" +
                "/status — Статус привязки / Link status\\n" +
                "/help — Справка / Help\\n\\n" +
                "Для привязки отправьте 6-значный код из Minecraft.\\n" +
                "To link, send the 6-digit code from Minecraft.");
        }
    }

    private void handleCallback(int userId, JsonObject payload) {
        if (!payload.has("action")) {
            debug("Callback without action from user " + userId);
            return;
        }

        String action = payload.get("action").getAsString();
        String confirmationId = payload.has("id") ? payload.get("id").getAsString() : null;

        if (confirmationId == null) {
            debug("Callback without confirmation ID from user " + userId);
            return;
        }

        debugUserAction(userId, "BUTTON", action + " for confirmation: " + confirmationId);

        if ("auth_approve".equals(action)) {
            handleApprove(confirmationId, userId);
        } else if ("auth_deny".equals(action)) {
            handleDeny(confirmationId, userId);
        }
    }

    private void handleApprove(String confirmationId, int userId) {
        debugUserAction(userId, "APPROVE", "Processing approval for: " + confirmationId);
        
        LoginConfirmation conf = confirmationService.approve(confirmationId);

        if (conf == null) {
            debugUserAction(userId, "APPROVE_ERROR", "Confirmation expired or not found");
            sendMessage(userId, "⏳ Запрос истёк / Request expired");
            return;
        }

        debugUserAction(userId, "APPROVE_SUCCESS", "Login approved for: " + conf.getUsername());
        sendMessage(userId,
                "✅ ВХОД ПОДТВЕРЖДЁН / LOGIN APPROVED\n\n" +
                "👤 " + conf.getUsername() + "\n" +
                "🌐 " + conf.getIpAddress() + "\n" +
                "📍 " + (conf.getLocation() != null ? conf.getLocation() : "—"));

        // Complete login in-game
        core.getPlatform().runAsync(() -> {
            UUID uuid = conf.getPlayerUuid();
            String ip = conf.getIpAddress();

            core.getSessionService().createSession(uuid, ip)
                    .thenAccept(session -> {
                        session.setTwoFactorVerified(true);
                        core.getStorage().saveSession(session);

                        core.getStorage().getAccount(uuid).thenAccept(optAcc -> {
                            if (optAcc.isPresent()) {
                                var account = optAcc.get();
                                core.setAuthenticated(uuid, true);
                                core.setInLimbo(uuid, false);

                                core.getPlatform().runSync(() -> {
                                    core.getPlatform().setLimboState(uuid, false);
                                    core.getPlatform().sendMessage(uuid,
                                            core.getMessageService().get("2fa.login-approved",
                                                    "method", "VK"));
                                    core.getPlatform().sendTitle(uuid,
                                            "§a✓", "§7VK ✓", 5, 40, 10);
                                });

                                core.getRoleService().applyRole(uuid, account.getRole());

                                core.getAuditService().log(
                                        AuditEventType.LOGIN_SUCCESS, uuid,
                                        account.getUsername(), ip,
                                        "2FA approved via VK"
                                );
                                
                                debugUserAction(userId, "LOGIN_COMPLETE", "Player " + account.getUsername() + " logged in");
                            }
                        });
                    });
        });
    }

    private void handleDeny(String confirmationId, int userId) {
        debugUserAction(userId, "DENY", "Processing denial for: " + confirmationId);
        
        LoginConfirmation conf = confirmationService.deny(confirmationId);

        if (conf == null) {
            debugUserAction(userId, "DENY_ERROR", "Confirmation expired or not found");
            sendMessage(userId, "⏳ Запрос истёк / Request expired");
            return;
        }

        debugUserAction(userId, "DENY_SUCCESS", "Login denied for: " + conf.getUsername());
        sendMessage(userId,
                "❌ ВХОД ОТКЛОНЁН / LOGIN DENIED\n\n" +
                "👤 " + conf.getUsername() + "\n" +
                "🌐 " + conf.getIpAddress() + "\n" +
                "📍 " + (conf.getLocation() != null ? conf.getLocation() : "—") + "\n\n" +
                "⚠️ Если это не вы — срочно смените пароль!\n" +
                "If this wasn't you — change your password immediately!");

        // Kick the player
        core.getPlatform().runSync(() -> {
            core.getPlatform().kickPlayer(conf.getPlayerUuid(),
                    core.getMessageService().get("2fa.login-denied-kick"));
        });

        core.getAuditService().log(
                AuditEventType.LOGIN_FAILURE, conf.getPlayerUuid(),
                conf.getUsername(), conf.getIpAddress(),
                "2FA DENIED via VK"
        );
    }

    private void sendMessage(int userId, String message) {
        try {
            debug("Sending message to user " + userId + ": " + message.substring(0, Math.min(message.length(), 50)) + "...");
            
            String urlStr = VK_API + "messages.send?"
                    + "user_id=" + userId
                    + "&message=" + URLEncoder.encode(message, StandardCharsets.UTF_8)
                    + "&random_id=" + System.currentTimeMillis()
                    + "&access_token=" + botToken
                    + "&v=" + API_VERSION;

            JsonObject response = executeVkRequest(urlStr);
            if (response != null && response.has("response")) {
                debug("Message sent successfully, message ID: " + response.get("response"));
            } else if (response != null && response.has("error")) {
                debug("ERROR sending message: " + response.get("error").toString());
            }
        } catch (Exception e) {
            debug("Error sending message: " + e.getMessage());
            if (isDebug()) {
                e.printStackTrace();
            }
        }
    }

    private JsonObject executeVkRequest(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        if (conn.getResponseCode() == 200) {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                return gson.fromJson(sb.toString(), JsonObject.class);
            }
        } else {
            debug("VK API HTTP error: " + conn.getResponseCode());
        }
        return null;
    }
}
