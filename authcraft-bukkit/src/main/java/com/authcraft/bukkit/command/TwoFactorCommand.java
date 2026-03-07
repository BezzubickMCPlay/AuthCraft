// com/authcraft/bukkit/command/TwoFactorCommand.java
package com.authcraft.bukkit.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.core.service.MessageService;
import com.authcraft.core.service.TwoFactorService;
import net.md_5.bungee.api.chat.ClickEvent;
import net.md_5.bungee.api.chat.HoverEvent;
import net.md_5.bungee.api.chat.TextComponent;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class TwoFactorCommand implements CommandExecutor, TabCompleter {

    private final AuthCraftCore core;
    private final MessageService msg;

    public TwoFactorCommand(AuthCraftCore core) {
        this.core = core;
        this.msg = core.getMessageService();
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command,
            String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(msg.get("admin.players-only"));
            return true;
        }

        UUID uuid = player.getUniqueId();

        if (args.length == 0) {
            msg.sendMultiline(uuid, "2fa.usage");
            return true;
        }

        String sub = args[0].toLowerCase();

        switch (sub) {
            case "enable" -> handleEnable(player, args);
            case "confirm" -> handleConfirm(player, args);
            case "disable" -> handleDisable(player, args);
            case "status" -> handleStatus(player);
            case "backup" -> handleBackup(player);
            default -> {
                if (core.isInLimbo(uuid)) {
                    handleVerify(player, args[0]);
                } else {
                    msg.sendMultiline(uuid, "2fa.usage");
                }
            }
        }

        return true;
    }

    private void handleEnable(Player player, String[] args) {
        UUID uuid = player.getUniqueId();

        if (!core.isAuthenticated(uuid)) {
            player.sendMessage(msg.get("password.must-login"));
            return;
        }

        // Check if this is a session-restored login (2FA should be blocked)
        if (isSessionRestoredLogin(uuid)) {
            player.sendMessage(msg.get("2fa.session-restore-blocked"));
            return;
        }

        TwoFactorMethod requestedMethod = TwoFactorMethod.TOTP;
        if (args.length >= 2) {
            try {
                requestedMethod = TwoFactorMethod.valueOf(args[1].toUpperCase());
            } catch (IllegalArgumentException e) {
                player.sendMessage(msg.get("2fa.unknown-method"));
                return;
            }
        }

        if (requestedMethod == TwoFactorMethod.NONE) {
            player.sendMessage(msg.get("2fa.unknown-method"));
            return;
        }

        if (!core.getTwoFactorService().isMethodAvailable(requestedMethod)) {
            player.sendMessage(msg.get("2fa.method-unavailable",
                "method", requestedMethod.name()));
            return;
        }

        // Make method effectively final for lambda
        final TwoFactorMethod method = requestedMethod;

        // Check if method is already enabled
        core.getStorage().getAccount(uuid).thenAccept(optAcc -> {
            if (optAcc.isPresent() && optAcc.get().isTwoFactorMethodEnabled(method)) {
                player.sendMessage(msg.get("2fa.already-enabled", "method", method.name()));
                return;
            }

            try {
                TwoFactorService.TwoFactorSetupResult result =
                    core.getAuthService().beginTwoFactorSetup(uuid, player.getName(), method);

                player.sendMessage(msg.get("2fa.setup-header"));
                player.sendMessage(msg.get("2fa.setup-method", "method", method.name()));
                player.sendMessage(msg.get("2fa.setup-secret", "secret", result.getSecret()));

                if (method == TwoFactorMethod.TOTP) {
                    // Show QR code URL and secret
                    player.sendMessage(msg.get("2fa.setup-qr"));
                    if (result.getQrCodeUrl() != null) {
                        // Show the secret key prominently for manual entry
                        player.sendMessage("§eSecret: §b" + result.getSecret());
                        player.sendMessage("§7Enter this secret in Google Authenticator or similar app");

                        // Create clickable link using a QR code generator service
                        String qrImageUrl = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data="
                            + java.net.URLEncoder.encode(result.getQrCodeUrl(), java.nio.charset.StandardCharsets.UTF_8);

                        TextComponent clickableLink = new TextComponent("§b§n[Click to view QR code image]");
                        clickableLink.setClickEvent(new ClickEvent(ClickEvent.Action.OPEN_URL, qrImageUrl));
                        clickableLink.setHoverEvent(new HoverEvent(HoverEvent.Action.SHOW_TEXT,
                            new TextComponent[] {new TextComponent("§eClick to open QR code in browser")}));
                        player.spigot().sendMessage(clickableLink);
                    }
                } else if (method == TwoFactorMethod.TELEGRAM) {
                    player.sendMessage(msg.get("2fa.setup-telegram",
                        "code", result.getSecret(), "bot", "AuthCraftBot"));
                } else if (method == TwoFactorMethod.VK) {
                    player.sendMessage(msg.get("2fa.setup-vk",
                        "code", result.getSecret(), "bot", "AuthCraft"));
                }

                player.sendMessage(msg.get("2fa.setup-confirm"));
            } catch (Exception e) {
                player.sendMessage(msg.get("error.generic"));
            }
        });
    }

    private void handleConfirm(Player player, String[] args) {
        UUID uuid = player.getUniqueId();

        if (args.length < 2) {
            player.sendMessage(msg.get("2fa.confirm-usage"));
            return;
        }

        core.getAuthService().confirmTwoFactorSetup(uuid, args[1])
            .thenAccept(backupCodes -> {
                player.sendMessage(msg.get("2fa.enabled"));
                player.sendMessage(msg.get("2fa.backup-header"));
                player.sendMessage(msg.get("2fa.backup-warning-save"));
                for (String code : backupCodes) {
                    player.sendMessage(msg.get("2fa.backup-code", "code", code));
                }
                player.sendMessage(msg.get("2fa.backup-footer"));
            })
            .exceptionally(ex -> {
                player.sendMessage(msg.get("2fa.confirm-invalid"));
                return null;
            });
    }

    private void handleDisable(Player player, String[] args) {
        UUID uuid = player.getUniqueId();

        // /2fa disable <password> [method] - disable all or specific method
        if (args.length < 2) {
            player.sendMessage(msg.get("2fa.disable-usage"));
            return;
        }

        String password = args[1];
        TwoFactorMethod specificMethod = null;

        // Check if a specific method is specified
        if (args.length >= 3) {
            try {
                specificMethod = TwoFactorMethod.valueOf(args[2].toUpperCase());
            } catch (IllegalArgumentException e) {
                player.sendMessage(msg.get("2fa.unknown-method"));
                return;
            }
        }

        if (specificMethod != null) {
            // Disable specific method - make effectively final
            final TwoFactorMethod methodToDisable = specificMethod;
            core.getAuthService().disableTwoFactorMethod(uuid, password, methodToDisable)
                .thenAccept(success -> player.sendMessage(
                    success ? msg.get("2fa.method-disabled", "method", methodToDisable.name())
                            : msg.get("2fa.wrong-password")
                ));
        } else {
            // Disable all methods
            core.getAuthService().disableTwoFactor(uuid, password)
                .thenAccept(success -> player.sendMessage(
                    success ? msg.get("2fa.disabled") : msg.get("2fa.wrong-password")
                ));
        }
    }

    private void handleStatus(Player player) {
        UUID uuid = player.getUniqueId();

        if (!core.isAuthenticated(uuid)) {
            player.sendMessage(msg.get("password.must-login"));
            return;
        }

        core.getStorage().getAccount(uuid).thenAccept(optAcc -> {
            if (optAcc.isEmpty()) {
                player.sendMessage(msg.get("error.generic"));
                return;
            }

            Account account = optAcc.get();
            Set<TwoFactorMethod> enabledMethods = account.getEnabledTwoFactorMethods();

            player.sendMessage(msg.get("2fa.status-header"));

            if (enabledMethods.isEmpty()) {
                player.sendMessage(msg.get("2fa.status-none"));
            } else {
                for (TwoFactorMethod m : enabledMethods) {
                    String status = "§a✓ " + m.name();
                    if (m == TwoFactorMethod.TOTP) {
                        status += " §7(Authenticator app)";
                    } else if (m == TwoFactorMethod.TELEGRAM) {
                        status += " §7(Telegram)";
                    } else if (m == TwoFactorMethod.VK) {
                        status += " §7(VK)";
                    } else if (m == TwoFactorMethod.EMAIL) {
                        status += " §7(Email)";
                    }
                    player.sendMessage(status);
                }
            }

            player.sendMessage(msg.get("2fa.status-footer"));
        });
    }

    private void handleBackup(Player player) {
        core.getTwoFactorService().regenerateBackupCodes(player.getUniqueId())
            .thenAccept(codes -> {
                player.sendMessage(msg.get("2fa.backup-header"));
                for (String code : codes) {
                    player.sendMessage(msg.get("2fa.backup-code", "code", code));
                }
                player.sendMessage(msg.get("2fa.backup-footer"));
            });
    }

    private void handleVerify(Player player, String code) {
        String ip = player.getAddress() != null
            ? player.getAddress().getAddress().getHostAddress() : "unknown";

        core.getAuthService().verify2FA(player.getUniqueId(), code, ip)
            .thenAccept(result -> {
                if (!result.isSuccessful()) {
                    player.sendMessage(result.getMessage());
                }
            });
    }

    /**
     * Check if the current login is from a session restore (not password login).
     */
    private boolean isSessionRestoredLogin(UUID uuid) {
        return core.getAuthService().isSessionRestoredLogin(uuid);
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command,
            String alias, String[] args) {
        List<String> completions = new ArrayList<>();

        if (args.length == 1) {
            // First argument - subcommands
            String partial = args[0].toLowerCase();
            for (String sub : Arrays.asList("enable", "confirm", "disable", "status", "backup")) {
                if (sub.startsWith(partial)) {
                    completions.add(sub);
                }
            }
        } else if (args.length == 2) {
            String sub = args[0].toLowerCase();
            String partial = args[1].toLowerCase();

            if (sub.equals("enable")) {
                // Suggest available methods
                for (TwoFactorMethod method : TwoFactorMethod.values()) {
                    if (method != TwoFactorMethod.NONE && method.name().toLowerCase().startsWith(partial)) {
                        completions.add(method.name().toLowerCase());
                    }
                }
            } else if (sub.equals("disable")) {
                // Suggest password placeholder
                completions.add("<password>");
            }
        } else if (args.length == 3) {
            String sub = args[0].toLowerCase();
            String partial = args[2].toLowerCase();

            if (sub.equals("disable")) {
                // Suggest enabled methods (synchronous for tab complete)
                if (sender instanceof Player player) {
                    var optAcc = core.getStorage().getAccount(player.getUniqueId()).join();
                    if (optAcc.isPresent()) {
                        for (TwoFactorMethod m : optAcc.get().getEnabledTwoFactorMethods()) {
                            if (m.name().toLowerCase().startsWith(partial)) {
                                completions.add(m.name().toLowerCase());
                            }
                        }
                    }
                }
            }
        }

        return completions;
    }
}
