// com/authcraft/integrations/vk/VKProvider.java
package com.authcraft.integrations.vk;

import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.model.LoginConfirmation;
import com.authcraft.core.model.TwoFactorMethod;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class VKProvider implements TwoFactorProvider {

    private final String botToken;
    private final boolean available;
    private final Gson gson = new Gson();

    private final Map<UUID, String> pendingCodes = new ConcurrentHashMap<>();
    private final Map<String, UUID> linkCodes = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String VK_API = "https://api.vk.com/method/";
    private static final String API_VERSION = "5.199";

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

    public VKProvider(String botToken) {
        this.botToken = botToken;
        this.available = botToken != null && !botToken.isEmpty();
    }

    public String getBotToken() {
        return botToken;
    }

    @Override
    public TwoFactorMethod getMethod() { return TwoFactorMethod.VK; }

    @Override
    public String generateSecret(UUID playerUuid, String username) {
        String linkCode = String.format("%06d", RANDOM.nextInt(1000000));
        linkCodes.put(linkCode, playerUuid);
        return linkCode;
    }

    @Override
    public boolean verifyCode(String secret, String code) {
        return false;
    }

    @Override
    public CompletableFuture<Boolean> sendCode(String userId, String code) {
        return CompletableFuture.completedFuture(true);
    }

    @Override
    public byte[] generateQrCode(String secret, String username, int size) {
        return null;
    }

    @Override
    public boolean isAvailable() { return available; }

    /**
     * Send login confirmation with inline keyboard buttons.
     */
    public CompletableFuture<Boolean> sendLoginConfirmation(
            String userId, LoginConfirmation confirmation) {
        return CompletableFuture.supplyAsync(() -> {
            if (!available || userId == null) return false;

            try {
                String message = buildLoginMessage(confirmation);

                // VK Keyboard with callback buttons
                JsonObject keyboard = buildKeyboard(confirmation.getConfirmationId());

                String urlStr = VK_API + "messages.send?"
                        + "user_id=" + userId
                        + "&message=" + URLEncoder.encode(message, StandardCharsets.UTF_8)
                        + "&keyboard=" + URLEncoder.encode(gson.toJson(keyboard), StandardCharsets.UTF_8)
                        + "&random_id=" + RANDOM.nextLong()
                        + "&access_token=" + botToken
                        + "&v=" + API_VERSION;

                return executeVkRequest(urlStr);
            } catch (Exception e) {
                return false;
            }
        });
    }

    /**
     * Send result notification after approve/deny.
     */
    public CompletableFuture<Boolean> sendConfirmationResult(
            String userId, LoginConfirmation confirmation, boolean approved) {
        return CompletableFuture.supplyAsync(() -> {
            if (!available || userId == null) return false;

            try {
                String emoji = approved ? "✅" : "❌";
                String status = approved ? "ПОДТВЕРЖДЁН" : "ОТКЛОНЁН";

                String message = emoji + " Вход " + status + "\n\n"
                        + "👤 Игрок: " + confirmation.getUsername() + "\n"
                        + "🌐 IP: " + confirmation.getIpAddress() + "\n"
                        + "📍 " + (confirmation.getLocation() != null
                        ? confirmation.getLocation() : "Неизвестно") + "\n"
                        + "🕐 " + TIME_FORMAT.format(confirmation.getCreatedAt());

                if (!approved) {
                    message += "\n\n⚠️ Если это не вы — срочно смените пароль!";
                }

                String urlStr = VK_API + "messages.send?"
                        + "user_id=" + userId
                        + "&message=" + URLEncoder.encode(message, StandardCharsets.UTF_8)
                        + "&random_id=" + RANDOM.nextLong()
                        + "&access_token=" + botToken
                        + "&v=" + API_VERSION;

                return executeVkRequest(urlStr);
            } catch (Exception e) {
                return false;
            }
        });
    }

    private String buildLoginMessage(LoginConfirmation confirmation) {
        StringBuilder sb = new StringBuilder();
        sb.append("🔐 Запрос на вход в AuthCraft\n\n");
        sb.append("👤 Игрок: ").append(confirmation.getUsername()).append("\n");
        sb.append("🌐 IP: ").append(confirmation.getIpAddress()).append("\n");

        if (confirmation.getLocation() != null
                && !confirmation.getLocation().equals("UNKNOWN")
                && !confirmation.getLocation().equals("LOCAL")) {
            sb.append("📍 Место: ").append(confirmation.getLocation()).append("\n");
        }

        sb.append("🕐 Время: ")
                .append(TIME_FORMAT.format(confirmation.getCreatedAt())).append("\n");
        sb.append("\n⏳ Запрос истекает через 2 минуты\n\n");
        sb.append("Если это не вы — нажмите «Отклонить» и смените пароль!");

        return sb.toString();
    }

    private JsonObject buildKeyboard(String confirmationId) {
        JsonObject keyboard = new JsonObject();
        // NOTE: For inline keyboards, VK API does NOT allow "one_time" field
        // Only set "inline" to true
        keyboard.addProperty("inline", true);

        // Build payload as JSON string (VK requires payload to be a string, not an object)
        JsonObject approvePayloadObj = new JsonObject();
        approvePayloadObj.addProperty("action", "auth_approve");
        approvePayloadObj.addProperty("id", confirmationId);
        String approvePayload = gson.toJson(approvePayloadObj);

        JsonObject denyPayloadObj = new JsonObject();
        denyPayloadObj.addProperty("action", "auth_deny");
        denyPayloadObj.addProperty("id", confirmationId);
        String denyPayload = gson.toJson(denyPayloadObj);

        // Approve button
        JsonObject approveAction = new JsonObject();
        approveAction.addProperty("type", "callback");
        approveAction.addProperty("label", "✅ Подтвердить");
        approveAction.addProperty("payload", approvePayload);  // Must be a string!

        JsonObject approveButton = new JsonObject();
        approveButton.add("action", approveAction);
        // Note: "color" is not allowed for inline keyboard buttons

        // Deny button
        JsonObject denyAction = new JsonObject();
        denyAction.addProperty("type", "callback");
        denyAction.addProperty("label", "❌ Отклонить");
        denyAction.addProperty("payload", denyPayload);  // Must be a string!

        JsonObject denyButton = new JsonObject();
        denyButton.add("action", denyAction);
        // Note: "color" is not allowed for inline keyboard buttons

        // Combine buttons into a row
        com.google.gson.JsonArray row = new com.google.gson.JsonArray();
        row.add(approveButton);
        row.add(denyButton);

        com.google.gson.JsonArray buttons = new com.google.gson.JsonArray();
        buttons.add(row);

        keyboard.add("buttons", buttons);
        return keyboard;
    }

    private boolean executeVkRequest(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        if (responseCode == 200) {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String response = reader.readLine();
                // Log the response for debugging
                System.out.println("[AuthCraft VK API] Response: " + response);
                if (response != null && response.contains("\"error\"")) {
                    System.out.println("[AuthCraft VK API] Error detected in response");
                    return false;
                }
                return response != null;
            }
        } else {
            // Log error response
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getErrorStream()))) {
                String errorResponse = reader.readLine();
                System.out.println("[AuthCraft VK API] HTTP " + responseCode + " Error: " + errorResponse);
            } catch (Exception e) {
                System.out.println("[AuthCraft VK API] HTTP " + responseCode + " (no error body)");
            }
            return false;
        }
    }

    public UUID handleLinkCode(String code) {
        return linkCodes.remove(code);
    }
}