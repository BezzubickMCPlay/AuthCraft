// com/authcraft/integrations/telegram/TelegramProvider.java
package com.authcraft.integrations.telegram;

import com.authcraft.core.api.TwoFactorProvider;
import com.authcraft.core.model.LoginConfirmation;
import com.authcraft.core.model.TwoFactorMethod;
import com.pengrad.telegrambot.TelegramBot;
import com.pengrad.telegrambot.model.request.InlineKeyboardButton;
import com.pengrad.telegrambot.model.request.InlineKeyboardMarkup;
import com.pengrad.telegrambot.model.request.ParseMode;
import com.pengrad.telegrambot.request.SendMessage;
import com.pengrad.telegrambot.response.SendResponse;

import java.security.SecureRandom;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class TelegramProvider implements TwoFactorProvider {

    private final TelegramBot bot;
    private final boolean available;
    private final String botUsername;

    private final Map<UUID, String> pendingCodes = new ConcurrentHashMap<>();
    private final Map<String, UUID> linkCodes = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

    public TelegramProvider(String botToken, String botUsername) {
        if (botToken != null && !botToken.isEmpty()) {
            this.bot = new TelegramBot(botToken);
            this.available = true;
        } else {
            this.bot = null;
            this.available = false;
        }
        this.botUsername = botUsername != null ? botUsername : "AuthCraftBot";
    }

    @Override
    public TwoFactorMethod getMethod() { return TwoFactorMethod.TELEGRAM; }

    @Override
    public String generateSecret(UUID playerUuid, String username) {
        String linkCode = String.format("%06d", RANDOM.nextInt(1000000));
        linkCodes.put(linkCode, playerUuid);
        return linkCode;
    }

    @Override
    public boolean verifyCode(String secret, String code) {
        return false; // Telegram uses button-based confirmation
    }

    @Override
    public CompletableFuture<Boolean> sendCode(String chatId, String code) {
        return CompletableFuture.completedFuture(true);
    }

    @Override
    public byte[] generateQrCode(String secret, String username, int size) {
        return null;
    }

    @Override
    public boolean isAvailable() { return available; }

    /**
     * Send login confirmation request with approve/deny buttons.
     */
    public CompletableFuture<Boolean> sendLoginConfirmation(
            String chatId, LoginConfirmation confirmation) {
        return CompletableFuture.supplyAsync(() -> {
            if (bot == null || chatId == null) return false;

            try {
                String message = buildLoginMessage(confirmation);

                InlineKeyboardMarkup keyboard = new InlineKeyboardMarkup(
                        new InlineKeyboardButton[] {
                                new InlineKeyboardButton("✅ Подтвердить / Confirm")
                                        .callbackData("auth_approve:" + confirmation.getConfirmationId()),
                                new InlineKeyboardButton("❌ Отклонить / Deny")
                                        .callbackData("auth_deny:" + confirmation.getConfirmationId())
                        }
                );

                SendResponse response = bot.execute(
                        new SendMessage(Long.parseLong(chatId), message)
                                .parseMode(ParseMode.HTML)
                                .replyMarkup(keyboard)
                );

                return response.isOk();
            } catch (Exception e) {
                return false;
            }
        });
    }

    /**
     * Send notification about approved/denied login.
     */
    public void sendConfirmationResult(String chatId,
                                       LoginConfirmation confirmation,
                                       boolean approved) {
        if (bot == null || chatId == null) return;

        String emoji = approved ? "✅" : "❌";
        String status = approved ? "ПОДТВЕРЖДЁН / APPROVED" : "ОТКЛОНЁН / DENIED";

        String message = emoji + " <b>Вход " + status + "</b>\n\n"
                + "👤 Игрок: <code>" + confirmation.getUsername() + "</code>\n"
                + "🌐 IP: <code>" + confirmation.getIpAddress() + "</code>\n"
                + "📍 " + (confirmation.getLocation() != null
                ? confirmation.getLocation() : "Неизвестно") + "\n"
                + "🕐 " + TIME_FORMAT.format(confirmation.getCreatedAt());

        bot.execute(
                new SendMessage(Long.parseLong(chatId), message)
                        .parseMode(ParseMode.HTML)
        );
    }

    /**
     * Send admin alert.
     */
    public void sendAdminAlert(String adminChatId, String alertMessage) {
        if (bot == null || adminChatId == null || adminChatId.isEmpty()) return;
        bot.execute(
                new SendMessage(Long.parseLong(adminChatId),
                        "🚨 <b>AuthCraft Security Alert</b>\n\n" + alertMessage)
                        .parseMode(ParseMode.HTML)
        );
    }

    private String buildLoginMessage(LoginConfirmation confirmation) {
        StringBuilder sb = new StringBuilder();
        sb.append("🔐 <b>Запрос на вход / Login Request</b>\n\n");
        sb.append("👤 Игрок / Player: <code>")
                .append(escapeHtml(confirmation.getUsername())).append("</code>\n");
        sb.append("🌐 IP: <code>")
                .append(confirmation.getIpAddress()).append("</code>\n");

        if (confirmation.getLocation() != null
                && !confirmation.getLocation().equals("UNKNOWN")
                && !confirmation.getLocation().equals("LOCAL")) {
            sb.append("📍 Место / Location: ")
                    .append(escapeHtml(confirmation.getLocation())).append("\n");
        }

        sb.append("🕐 Время / Time: ")
                .append(TIME_FORMAT.format(confirmation.getCreatedAt())).append("\n");
        sb.append("\n");
        sb.append("⏳ Запрос истекает через 2 минуты / Expires in 2 minutes\n\n");
        sb.append("<i>Если это не вы — нажмите «Отклонить» и смените пароль!\n");
        sb.append("If this wasn't you — press \"Deny\" and change your password!</i>");

        return sb.toString();
    }

    private String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    public UUID handleLinkCode(String code) {
        return linkCodes.remove(code);
    }

    public TelegramBot getBot() { return bot; }
    public String getBotUsername() { return botUsername; }
}