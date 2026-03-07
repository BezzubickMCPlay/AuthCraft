// com/authcraft/integrations/telegram/TelegramBotPoller.java
package com.authcraft.integrations.telegram;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.LoginConfirmation;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.core.service.LoginConfirmationService;
import com.pengrad.telegrambot.TelegramBot;
import com.pengrad.telegrambot.UpdatesListener;
import com.pengrad.telegrambot.model.CallbackQuery;
import com.pengrad.telegrambot.model.Message;
import com.pengrad.telegrambot.model.Update;
import com.pengrad.telegrambot.request.AnswerCallbackQuery;
import com.pengrad.telegrambot.request.EditMessageText;
import com.pengrad.telegrambot.request.SendMessage;
import com.pengrad.telegrambot.model.request.ParseMode;

import java.util.UUID;
import java.util.logging.Logger;

public class TelegramBotPoller {

    private final TelegramBot bot;
    private final TelegramProvider provider;
    private final AuthCraftCore core;
    private final AuthCraftConfig config;
    private final LoginConfirmationService confirmationService;
    private final Logger logger;

    public TelegramBotPoller(TelegramBot bot, TelegramProvider provider,
            AuthCraftCore core,
            LoginConfirmationService confirmationService,
            Logger logger) {
        this.bot = bot;
        this.provider = provider;
        this.core = core;
        this.config = core.getConfig();
        this.confirmationService = confirmationService;
        this.logger = logger;
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
            logger.info("[AuthCraft TG DEBUG] " + message);
        }
    }

    /**
     * Debug log with user interaction - always shown in debug mode
     */
    private void debugUserAction(long chatId, String action, String details) {
        if (isDebug()) {
            logger.info("[AuthCraft TG] Chat " + chatId + " -> " + action + ": " + details);
        }
    }

    public void startPolling() {
        debug("Starting Telegram polling initialization...");
        
        bot.setUpdatesListener(updates -> {
            debug("Received " + updates.size() + " update(s)");
            for (Update update : updates) {
                try {
                    if (update.callbackQuery() != null) {
                        debug("Processing callback query");
                        handleCallback(update.callbackQuery());
                    } else if (update.message() != null) {
                        debug("Processing message");
                        handleMessage(update.message());
                    }
                } catch (Exception e) {
                    logger.warning("[AuthCraft TG] Error: " + e.getMessage());
                    if (isDebug()) {
                        e.printStackTrace();
                    }
                }
            }
            return UpdatesListener.CONFIRMED_UPDATES_ALL;
        }, e -> {
            if (e != null) {
                logger.warning("[AuthCraft TG] Poll error: " + e.getMessage());
                if (isDebug()) {
                    e.printStackTrace();
                }
            }
        });
        logger.info("[AuthCraft] Telegram bot polling started" + (isDebug() ? " (DEBUG MODE)" : ""));
    }

    public void stopPolling() {
        debug("Stopping Telegram polling...");
        bot.removeGetUpdatesListener();
        debug("Telegram polling stopped");
    }

    // ═══════════════════════════════════
    // Callback кнопок (подтвердить/отклонить)
    // ═══════════════════════════════════

    private void handleCallback(CallbackQuery callback) {
        String data = callback.data();
        long chatId = callback.message().chat().id();
        int messageId = callback.message().messageId();

        if (data == null) {
            debug("Callback with null data from chat " + chatId);
            return;
        }

        debugUserAction(chatId, "CALLBACK", data);

        if (data.startsWith("auth_approve:")) {
            String confirmationId = data.substring("auth_approve:".length());
            debugUserAction(chatId, "APPROVE_BUTTON", confirmationId);
            handleApprove(confirmationId, chatId, messageId, callback.id());
        } else if (data.startsWith("auth_deny:")) {
            String confirmationId = data.substring("auth_deny:".length());
            debugUserAction(chatId, "DENY_BUTTON", confirmationId);
            handleDeny(confirmationId, chatId, messageId, callback.id());
        } else {
            debug("Unknown callback data: " + data);
        }
    }

    private void handleApprove(String confirmationId, long chatId,
            int messageId, String callbackId) {
        debugUserAction(chatId, "APPROVE", "Processing approval for: " + confirmationId);
        
        LoginConfirmation conf = confirmationService.approve(confirmationId);

        if (conf == null) {
            debugUserAction(chatId, "APPROVE_ERROR", "Confirmation expired or not found");
            bot.execute(new AnswerCallbackQuery(callbackId)
                    .text("⏳ Запрос истёк / Request expired")
                    .showAlert(true));
            return;
        }

        // Answer callback
        bot.execute(new AnswerCallbackQuery(callbackId)
                .text("✅ Вход подтверждён! / Login approved!"));

        debugUserAction(chatId, "APPROVE_SUCCESS", "Login approved for: " + conf.getUsername());

        // Edit message — remove buttons
        bot.execute(new EditMessageText(chatId, messageId,
                "✅ <b>ВХОД ПОДТВЕРЖДЁН / LOGIN APPROVED</b>\n\n"
                        + "👤 " + conf.getUsername() + "\n"
                        + "🌐 " + conf.getIpAddress() + "\n"
                        + "📍 " + (conf.getLocation() != null ? conf.getLocation() : "—"))
                .parseMode(ParseMode.HTML));

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
                                                    "method", "Telegram"));
                                    core.getPlatform().sendTitle(uuid,
                                            "§a✓", "§7Telegram ✓", 5, 40, 10);
                                });

                                core.getRoleService().applyRole(uuid, account.getRole());

                                core.getAuditService().log(
                                        AuditEventType.LOGIN_SUCCESS, uuid,
                                        account.getUsername(), ip,
                                        "2FA approved via Telegram"
                                );
                                
                                debugUserAction(chatId, "LOGIN_COMPLETE", "Player " + account.getUsername() + " logged in");
                            }
                        });
                    });
        });
    }

    private void handleDeny(String confirmationId, long chatId,
            int messageId, String callbackId) {
        debugUserAction(chatId, "DENY", "Processing denial for: " + confirmationId);
        
        LoginConfirmation conf = confirmationService.deny(confirmationId);

        if (conf == null) {
            debugUserAction(chatId, "DENY_ERROR", "Confirmation expired or not found");
            bot.execute(new AnswerCallbackQuery(callbackId)
                    .text("⏳ Запрос истёк / Request expired")
                    .showAlert(true));
            return;
        }

        // Answer callback
        bot.execute(new AnswerCallbackQuery(callbackId)
                .text("❌ Вход отклонён! / Login denied!"));

        debugUserAction(chatId, "DENY_SUCCESS", "Login denied for: " + conf.getUsername());

        // Edit message — remove buttons
        bot.execute(new EditMessageText(chatId, messageId,
                "❌ <b>ВХОД ОТКЛОНЁН / LOGIN DENIED</b>\n\n"
                        + "👤 " + conf.getUsername() + "\n"
                        + "🌐 " + conf.getIpAddress() + "\n"
                        + "📍 " + (conf.getLocation() != null ? conf.getLocation() : "—") + "\n\n"
                        + "⚠️ <i>Если это не вы — срочно смените пароль!\n"
                        + "If this wasn't you — change your password immediately!</i>")
                .parseMode(ParseMode.HTML));

        // Kick the player
        core.getPlatform().runSync(() -> {
            core.getPlatform().kickPlayer(conf.getPlayerUuid(),
                    core.getMessageService().get("2fa.login-denied-kick"));
        });

        core.getAuditService().log(
                AuditEventType.LOGIN_FAILURE, conf.getPlayerUuid(),
                conf.getUsername(), conf.getIpAddress(),
                "2FA DENIED via Telegram"
        );
    }

    // ═══════════════════════════════════
    // Текстовые сообщения (привязка и т.д.)
    // ═══════════════════════════════════

    private void handleMessage(Message message) {
        String text = message.text();
        long chatId = message.chat().id();

        if (text == null) {
            debug("Message with null text from chat " + chatId);
            return;
        }

        debugUserAction(chatId, "MESSAGE", text);

        if (text.startsWith("/start")) {
            debugUserAction(chatId, "/START", "Sending welcome message");
            bot.execute(new SendMessage(chatId,
                    "🔐 <b>AuthCraft 2FA Bot</b>\n\n"
                            + "Отправьте код привязки для подключения аккаунта Minecraft.\n"
                            + "Send your link code to connect your Minecraft account.\n\n"
                            + "После привязки вы будете получать запросы на подтверждение входа "
                            + "с кнопками ✅/❌.\n"
                            + "Once linked, you'll receive login requests with approve/deny buttons.")
                    .parseMode(ParseMode.HTML));
            return;
        }

        if (text.startsWith("/help")) {
            debugUserAction(chatId, "/HELP", "Sending help message");
            bot.execute(new SendMessage(chatId,
                    "📋 <b>Команды / Commands:</b>\n\n"
                            + "/start — Приветствие / Welcome\n"
                            + "/status — Статус привязки / Link status\n"
                            + "Отправьте 6-значный код / Send 6-digit code — Привязка аккаунта / Link account")
                    .parseMode(ParseMode.HTML));
            return;
        }

        if (text.startsWith("/status")) {
            debugUserAction(chatId, "/STATUS", "Checking link status");
            // Check if this chatId is linked to any account
            core.getStorage().getAllAccounts().thenAccept(accounts -> {
                String chatIdStr = String.valueOf(chatId);
                var linked = accounts.stream()
                        .filter(a -> chatIdStr.equals(a.getTelegramChatId()))
                        .findFirst();

                if (linked.isPresent()) {
                    debugUserAction(chatId, "/STATUS", "Linked to: " + linked.get().getUsername());
                    bot.execute(new SendMessage(chatId,
                            "✅ Привязан к / Linked to: <code>"
                                    + linked.get().getUsername() + "</code>")
                            .parseMode(ParseMode.HTML));
                } else {
                    debugUserAction(chatId, "/STATUS", "Not linked");
                    bot.execute(new SendMessage(chatId,
                            "❌ Не привязан / Not linked.\n"
                                    + "Используйте /2fa enable telegram в Minecraft.\n"
                                    + "Use /2fa enable telegram in Minecraft."));
                }
            });
            return;
        }

        // Try as link code
        String code = text.trim();
        if (code.matches("\\d{6}")) {
            debugUserAction(chatId, "LINK_CODE", "Attempting to link with code: " + code);
            UUID playerUuid = provider.handleLinkCode(code);
            if (playerUuid != null) {
                debugUserAction(chatId, "LINK_CODE", "Valid code! Player UUID: " + playerUuid);
                core.getStorage().getAccount(playerUuid).thenAccept(opt -> {
                    if (opt.isPresent()) {
                        var account = opt.get();
                        account.setTelegramChatId(String.valueOf(chatId));
                        account.enableTwoFactorMethod(TwoFactorMethod.TELEGRAM);
                        account.setTwoFactorSecretForMethod(TwoFactorMethod.TELEGRAM, code);
                        core.getStorage().saveAccount(account);

                        debugUserAction(chatId, "LINK_SUCCESS", "Account linked: " + account.getUsername());
                        bot.execute(new SendMessage(chatId,
                                "✅ <b>Аккаунт привязан! / Account linked!</b>\n\n"
                                        + "👤 Игрок / Player: <code>" + account.getUsername() + "</code>\n\n"
                                        + "✅ Двухфакторная аутентификация включена!\n"
                                        + "✅ Two-factor authentication enabled!\n\n"
                                        + "Теперь при входе вы будете получать запрос с кнопками подтверждения.\n"
                                        + "You will now receive login requests with approve/deny buttons.")
                                .parseMode(ParseMode.HTML));

                        // Notify player that 2FA is now enabled
                        core.getPlatform().sendMessage(playerUuid,
                                core.getMessageService().get("2fa.enabled"));

                        core.getAuditService().log(
                                AuditEventType.TWO_FACTOR_ENABLE,
                                playerUuid, account.getUsername(),
                                "telegram:" + chatId,
                                "Telegram linked"
                        );
                    }
                });
            } else {
                debugUserAction(chatId, "LINK_ERROR", "Invalid or expired code");
                bot.execute(new SendMessage(chatId,
                        "❌ Неверный или истёкший код. / Invalid or expired code.\n"
                                + "Используйте /2fa enable telegram в Minecraft.\n"
                                + "Use /2fa enable telegram in Minecraft."));
            }
        } else {
            debugUserAction(chatId, "UNKNOWN", "Unrecognized message format: " + text);
        }
    }
}
