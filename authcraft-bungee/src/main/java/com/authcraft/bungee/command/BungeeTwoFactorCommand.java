// com/authcraft/bungee/command/BungeeTwoFactorCommand.java
package com.authcraft.bungee.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.core.service.TwoFactorService;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

public class BungeeTwoFactorCommand extends Command {

    private final AuthCraftCore core;

    public BungeeTwoFactorCommand(AuthCraftCore core) {
        super("2fa");
        this.core = core;
    }

    @Override
    public void execute(CommandSender sender, String[] args) {
        if (!(sender instanceof ProxiedPlayer player)) {
            sender.sendMessage(TextComponent.fromLegacyText("§cPlayers only."));
            return;
        }

        if (args.length == 0) {
            player.sendMessage(TextComponent.fromLegacyText(
                    "§e/2fa enable [totp|telegram|vk|email] | confirm <code> | disable <password> | backup"));
            return;
        }

        var uuid = player.getUniqueId();
        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "unknown";

        switch (args[0].toLowerCase()) {
            case "enable" -> {
                if (!core.isAuthenticated(uuid)) {
                    player.sendMessage(TextComponent.fromLegacyText("§cYou must be logged in."));
                    return;
                }
                TwoFactorMethod method = TwoFactorMethod.TOTP;
                if (args.length >= 2) {
                    try { method = TwoFactorMethod.valueOf(args[1].toUpperCase()); }
                    catch (Exception e) {
                        player.sendMessage(TextComponent.fromLegacyText(
                                "§cUnknown method. Use: totp, telegram, vk, email"));
                        return;
                    }
                }
                try {
                    var result = core.getAuthService().beginTwoFactorSetup(uuid, player.getName(), method);
                    player.sendMessage(TextComponent.fromLegacyText("§aSecret: " + result.getSecret()));
                    player.sendMessage(TextComponent.fromLegacyText("§eConfirm: /2fa confirm <code>"));
                } catch (Exception e) {
                    player.sendMessage(TextComponent.fromLegacyText("§cError: " + e.getMessage()));
                }
            }
            case "confirm" -> {
                if (args.length < 2) {
                    player.sendMessage(TextComponent.fromLegacyText("§eUsage: /2fa confirm <code>"));
                    return;
                }
                core.getAuthService().confirmTwoFactorSetup(uuid, args[1])
                        .thenAccept(codes -> {
                            player.sendMessage(TextComponent.fromLegacyText("§a✓ 2FA enabled! Backup codes:"));
                            for (String code : codes) {
                                player.sendMessage(TextComponent.fromLegacyText("§7  " + code));
                            }
                        })
                        .exceptionally(ex -> {
                            player.sendMessage(TextComponent.fromLegacyText("§cInvalid code."));
                            return null;
                        });
            }
            case "disable" -> {
                if (args.length < 2) {
                    player.sendMessage(TextComponent.fromLegacyText("§eUsage: /2fa disable <password>"));
                    return;
                }
                core.getAuthService().disableTwoFactor(uuid, args[1])
                        .thenAccept(ok -> player.sendMessage(TextComponent.fromLegacyText(
                                ok ? "§a2FA disabled." : "§cWrong password.")));
            }
            case "backup" -> {
                core.getTwoFactorService().regenerateBackupCodes(uuid)
                        .thenAccept(codes -> {
                            player.sendMessage(TextComponent.fromLegacyText("§aNew backup codes:"));
                            for (String c : codes) {
                                player.sendMessage(TextComponent.fromLegacyText("§7  " + c));
                            }
                        });
            }
            default -> {
                // Treat as 2FA code during login
                if (core.isInLimbo(uuid)) {
                    core.getAuthService().verify2FA(uuid, args[0], ip)
                            .thenAccept(result -> {
                                if (!result.isSuccessful()) {
                                    player.sendMessage(TextComponent.fromLegacyText(result.getMessage()));
                                }
                            });
                }
            }
        }
    }
}