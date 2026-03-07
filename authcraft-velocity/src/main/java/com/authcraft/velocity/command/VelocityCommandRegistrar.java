// com/authcraft/velocity/command/VelocityCommandRegistrar.java
package com.authcraft.velocity.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.security.SecurityChain;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

public class VelocityCommandRegistrar {

    private static final LegacyComponentSerializer LEGACY =
            LegacyComponentSerializer.legacySection();

    public static void registerAll(ProxyServer server, AuthCraftCore core,
                                   SecurityChain securityChain) {

        // /register
        server.getCommandManager().register("register", (SimpleCommand) invocation -> {
            if (!(invocation.source() instanceof Player player)) return;
            String[] args = invocation.arguments();
            if (args.length != 2) {
                player.sendMessage(LEGACY.deserialize("§eUsage: /register <password> <password>"));
                return;
            }
            String ip = player.getRemoteAddress().getAddress().getHostAddress();
            core.getAuthService().register(player.getUniqueId(), player.getUsername(), args[0], args[1], ip)
                    .thenAccept(r -> { if (!r.isSuccessful()) player.sendMessage(LEGACY.deserialize(r.getMessage())); })
                    .exceptionally(ex -> { player.sendMessage(LEGACY.deserialize("§cError: " + ex.getMessage())); return null; });
        }, "reg");

        // /login
        server.getCommandManager().register("login", (SimpleCommand) invocation -> {
            if (!(invocation.source() instanceof Player player)) return;
            String[] args = invocation.arguments();
            if (args.length != 1) {
                player.sendMessage(LEGACY.deserialize("§eUsage: /login <password>"));
                return;
            }
            String ip = player.getRemoteAddress().getAddress().getHostAddress();
            core.getAuthService().login(player.getUniqueId(), player.getUsername(), args[0], ip)
                    .thenAccept(r -> {
                        if (!r.isSuccessful() && r.getStatus() !=
                                com.authcraft.core.model.AuthResult.Status.REQUIRES_2FA)
                            player.sendMessage(LEGACY.deserialize(r.getMessage()));
                    })
                    .exceptionally(ex -> { player.sendMessage(LEGACY.deserialize("§cError: " + ex.getMessage())); return null; });
        }, "l");

        // /changepassword
        server.getCommandManager().register("changepassword", (SimpleCommand) invocation -> {
            if (!(invocation.source() instanceof Player player)) return;
            String[] args = invocation.arguments();
            if (args.length != 2) {
                player.sendMessage(LEGACY.deserialize("§eUsage: /changepassword <old> <new>"));
                return;
            }
            core.getAuthService().changePassword(player.getUniqueId(), args[0], args[1])
                    .thenAccept(r -> player.sendMessage(LEGACY.deserialize(r.getMessage())));
        }, "cp", "passwd");

        // /2fa
        server.getCommandManager().register("2fa", (SimpleCommand) invocation -> {
            if (!(invocation.source() instanceof Player player)) return;
            String[] args = invocation.arguments();
            if (args.length == 0) {
                player.sendMessage(LEGACY.deserialize("§e/2fa enable|confirm|disable|backup|<code>"));
                return;
            }
            var uuid = player.getUniqueId();
            String ip = player.getRemoteAddress().getAddress().getHostAddress();

            switch (args[0].toLowerCase()) {
                case "enable" -> {
                    TwoFactorMethod m = TwoFactorMethod.TOTP;
                    if (args.length >= 2) try { m = TwoFactorMethod.valueOf(args[1].toUpperCase()); } catch (Exception ignored) {}
                    try {
                        var r = core.getAuthService().beginTwoFactorSetup(uuid, player.getUsername(), m);
                        player.sendMessage(LEGACY.deserialize("§aSecret: " + r.getSecret()));
                        player.sendMessage(LEGACY.deserialize("§eConfirm: /2fa confirm <code>"));
                    } catch (Exception e) { player.sendMessage(LEGACY.deserialize("§c" + e.getMessage())); }
                }
                case "confirm" -> {
                    if (args.length < 2) return;
                    core.getAuthService().confirmTwoFactorSetup(uuid, args[1])
                            .thenAccept(codes -> {
                                player.sendMessage(LEGACY.deserialize("§a✓ 2FA enabled!"));
                                codes.forEach(c -> player.sendMessage(LEGACY.deserialize("§7  " + c)));
                            }).exceptionally(ex -> { player.sendMessage(LEGACY.deserialize("§cInvalid code.")); return null; });
                }
                case "disable" -> {
                    if (args.length < 2) return;
                    core.getAuthService().disableTwoFactor(uuid, args[1])
                            .thenAccept(ok -> player.sendMessage(LEGACY.deserialize(ok ? "§aDisabled." : "§cWrong password.")));
                }
                case "backup" -> {
                    core.getTwoFactorService().regenerateBackupCodes(uuid)
                            .thenAccept(codes -> codes.forEach(c -> player.sendMessage(LEGACY.deserialize("§7  " + c))));
                }
                default -> {
                    if (core.isInLimbo(uuid))
                        core.getAuthService().verify2FA(uuid, args[0], ip)
                                .thenAccept(r -> { if (!r.isSuccessful()) player.sendMessage(LEGACY.deserialize(r.getMessage())); });
                }
            }
        });

        // /authcraft
        server.getCommandManager().register("authcraft", (SimpleCommand) invocation -> {
            if (!invocation.source().hasPermission("authcraft.admin")) return;
            String[] args = invocation.arguments();
            var adminUuid = invocation.source() instanceof Player p ? p.getUniqueId() : null;

            if (args.length == 0) {
                invocation.source().sendMessage(LEGACY.deserialize(
                        "§e/authcraft reset2fa|unlock|setrole|info|antibot|reload"));
                return;
            }

            switch (args[0].toLowerCase()) {
                case "reset2fa" -> {
                    if (args.length < 2) return;
                    core.getAuthService().adminReset2FA(adminUuid, args[1])
                            .thenAccept(ok -> invocation.source().sendMessage(
                                    LEGACY.deserialize(ok ? "§aDone." : "§cNot found.")));
                }
                case "unlock" -> {
                    if (args.length < 2) return;
                    core.getAuthService().adminUnlock(adminUuid, args[1])
                            .thenAccept(ok -> invocation.source().sendMessage(
                                    LEGACY.deserialize(ok ? "§aUnlocked." : "§cNot found.")));
                }
                case "setrole" -> {
                    if (args.length < 3) return;
                    core.getAuthService().setRole(adminUuid, args[1], args[2])
                            .thenAccept(ok -> invocation.source().sendMessage(
                                    LEGACY.deserialize(ok ? "§aRole set." : "§cFailed.")));
                }
                case "info" -> {
                    if (args.length < 2) return;
                    core.getStorage().getAccountByName(args[1]).thenAccept(opt -> {
                        if (opt.isEmpty()) { invocation.source().sendMessage(LEGACY.deserialize("§cNot found.")); return; }
                        var a = opt.get();
                        invocation.source().sendMessage(LEGACY.deserialize(
                                "§eUUID: §f" + a.getUuid() + " §eRole: §f" + a.getRole()
                                        + " §e2FA: §f" + a.getTwoFactorMethod() + " §eStatus: §f" + a.getStatus()));
                    });
                }
                case "antibot" -> invocation.source().sendMessage(LEGACY.deserialize(
                        "§eAttack: " + (securityChain.getAntiBot().isAttackMode() ? "§cACTIVE" : "§aOff")));
                case "reload" -> {
                    core.getRoleService().loadRoles();
                    invocation.source().sendMessage(LEGACY.deserialize("§aReloaded."));
                }
            }
        }, "ac");
    }
}