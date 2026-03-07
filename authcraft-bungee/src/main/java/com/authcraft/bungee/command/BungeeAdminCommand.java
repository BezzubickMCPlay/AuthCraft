// com/authcraft/bungee/command/BungeeAdminCommand.java
package com.authcraft.bungee.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.security.SecurityChain;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

public class BungeeAdminCommand extends Command {

    private final AuthCraftCore core;
    private final SecurityChain securityChain;

    public BungeeAdminCommand(AuthCraftCore core, SecurityChain securityChain) {
        super("authcraft", "authcraft.admin", "ac");
        this.core = core;
        this.securityChain = securityChain;
    }

    @Override
    public void execute(CommandSender sender, String[] args) {
        if (!sender.hasPermission("authcraft.admin")) {
            sender.sendMessage(TextComponent.fromLegacyText("§cNo permission."));
            return;
        }

        var adminUuid = sender instanceof ProxiedPlayer p ? p.getUniqueId() : null;

        if (args.length == 0) {
            sender.sendMessage(TextComponent.fromLegacyText(
                    "§e/authcraft reset2fa|unlock|setrole|info|antibot|reload"));
            return;
        }

        switch (args[0].toLowerCase()) {
            case "reset2fa" -> {
                if (args.length < 2) { sender.sendMessage(TextComponent.fromLegacyText("§eUsage: /ac reset2fa <user>")); return; }
                core.getAuthService().adminReset2FA(adminUuid, args[1])
                        .thenAccept(ok -> sender.sendMessage(TextComponent.fromLegacyText(
                                ok ? "§a2FA reset for " + args[1] : "§cPlayer not found.")));
            }
            case "unlock" -> {
                if (args.length < 2) { sender.sendMessage(TextComponent.fromLegacyText("§eUsage: /ac unlock <user>")); return; }
                core.getAuthService().adminUnlock(adminUuid, args[1])
                        .thenAccept(ok -> sender.sendMessage(TextComponent.fromLegacyText(
                                ok ? "§aUnlocked: " + args[1] : "§cPlayer not found.")));
            }
            case "setrole" -> {
                if (args.length < 3) { sender.sendMessage(TextComponent.fromLegacyText("§eUsage: /ac setrole <user> <role>")); return; }
                core.getAuthService().setRole(adminUuid, args[1], args[2])
                        .thenAccept(ok -> sender.sendMessage(TextComponent.fromLegacyText(
                                ok ? "§aRole set." : "§cFailed.")));
            }
            case "info" -> {
                if (args.length < 2) { sender.sendMessage(TextComponent.fromLegacyText("§eUsage: /ac info <user>")); return; }
                core.getStorage().getAccountByName(args[1]).thenAccept(opt -> {
                    if (opt.isEmpty()) { sender.sendMessage(TextComponent.fromLegacyText("§cNot found.")); return; }
                    var a = opt.get();
                    sender.sendMessage(TextComponent.fromLegacyText("§eUUID: §f" + a.getUuid()));
                    sender.sendMessage(TextComponent.fromLegacyText("§eRole: §f" + a.getRole()));
                    sender.sendMessage(TextComponent.fromLegacyText("§e2FA: §f" + a.getTwoFactorMethod()));
                    sender.sendMessage(TextComponent.fromLegacyText("§eStatus: §f" + a.getStatus()));
                });
            }
            case "antibot" -> {
                var ab = securityChain.getAntiBot();
                sender.sendMessage(TextComponent.fromLegacyText(
                        "§eAttack mode: " + (ab.isAttackMode() ? "§cACTIVE" : "§aOff")
                                + " §eBlocked IPs: §f" + ab.getBlockedIps().size()));
            }
            case "reload" -> {
                core.getRoleService().loadRoles();
                sender.sendMessage(TextComponent.fromLegacyText("§aReloaded."));
            }
        }
    }
}