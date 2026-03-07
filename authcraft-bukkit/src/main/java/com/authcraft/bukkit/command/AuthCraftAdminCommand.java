// com/authcraft/bukkit/command/AuthCraftAdminCommand.java
package com.authcraft.bukkit.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.service.MessageService;
import com.authcraft.security.SecurityChain;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Map;
import java.util.UUID;

public class AuthCraftAdminCommand implements CommandExecutor {

    private final AuthCraftCore core;
    private final SecurityChain securityChain;
    private final MessageService msg;

    public AuthCraftAdminCommand(AuthCraftCore core, SecurityChain securityChain) {
        this.core = core;
        this.securityChain = securityChain;
        this.msg = core.getMessageService();
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command,
                             String label, String[] args) {
        if (!sender.hasPermission("authcraft.admin")) {
            sender.sendMessage(msg.get("admin.no-permission"));
            return true;
        }

        if (args.length == 0) {
            for (String line : msg.get("admin.usage").split("\n")) {
                sender.sendMessage(line);
            }
            return true;
        }

        UUID adminUuid = sender instanceof Player p ? p.getUniqueId() : null;

        switch (args[0].toLowerCase()) {
            case "reset2fa" -> {
                if (args.length < 2) {
                    sender.sendMessage(msg.get("admin.reset2fa-usage"));
                    return true;
                }
                core.getAuthService().adminReset2FA(adminUuid, args[1])
                        .thenAccept(ok -> sender.sendMessage(
                                ok ? msg.get("admin.reset2fa-success", "player", args[1])
                                        : msg.get("admin.not-found")));
            }

            case "unlock" -> {
                if (args.length < 2) {
                    sender.sendMessage(msg.get("admin.unlock-usage"));
                    return true;
                }
                core.getAuthService().adminUnlock(adminUuid, args[1])
                        .thenAccept(ok -> sender.sendMessage(
                                ok ? msg.get("admin.unlock-success", "player", args[1])
                                        : msg.get("admin.not-found")));
            }

            case "setrole" -> {
                if (args.length < 3) {
                    sender.sendMessage(msg.get("admin.setrole-usage"));
                    return true;
                }
                core.getAuthService().setRole(adminUuid, args[1], args[2])
                        .thenAccept(ok -> sender.sendMessage(
                                ok ? msg.get("admin.setrole-success",
                                        "player", args[1], "role", args[2])
                                        : msg.get("admin.setrole-failed")));
            }

            case "info" -> {
                if (args.length < 2) {
                    sender.sendMessage(msg.get("admin.info-usage"));
                    return true;
                }
                core.getStorage().getAccountByName(args[1]).thenAccept(opt -> {
                    if (opt.isEmpty()) {
                        sender.sendMessage(msg.get("admin.not-found"));
                        return;
                    }
                    var a = opt.get();
                    sender.sendMessage(msg.get("admin.info-header"));
                    sender.sendMessage(msg.get("admin.info-uuid", "uuid", a.getUuid().toString()));
                    sender.sendMessage(msg.get("admin.info-role", "role", a.getRole()));
                    sender.sendMessage(msg.get("admin.info-status", "status", a.getStatus().name()));
                    sender.sendMessage(msg.get("admin.info-2fa", "method", a.getTwoFactorMethod().name()));
                    sender.sendMessage(msg.get("admin.info-hash", "algorithm", a.getHashAlgorithm().getId()));
                    sender.sendMessage(msg.get("admin.info-failed", "attempts",
                            String.valueOf(a.getFailedLoginAttempts())));
                    sender.sendMessage(msg.get("admin.info-last-ip", "ip",
                            a.getLastLoginIp() != null ? a.getLastLoginIp() : "N/A"));
                    sender.sendMessage(msg.get("admin.info-last-login", "date",
                            a.getLastLoginDate() != null ? a.getLastLoginDate().toString() : "Never"));
                    sender.sendMessage(msg.get("admin.info-registered", "date",
                            a.getCreatedAt().toString()));
                });
            }

            case "antibot" -> {
                var ab = securityChain.getAntiBot();
                sender.sendMessage(msg.get("admin.antibot-header"));
                sender.sendMessage(msg.get("admin.antibot-mode", "status",
                        ab.isAttackMode() ? msg.get("admin.antibot-mode-active")
                                : msg.get("admin.antibot-mode-off")));
                sender.sendMessage(msg.get("admin.antibot-blocked", "count",
                        String.valueOf(ab.getBlockedIps().size())));
            }

            case "reload" -> {
                core.getRoleService().loadRoles();
                core.getMessageService().reload();
                sender.sendMessage(msg.get("admin.reloaded"));
            }

            default -> {
                for (String line : msg.get("admin.usage").split("\n")) {
                    sender.sendMessage(line);
                }
            }
        }

        return true;
    }
}