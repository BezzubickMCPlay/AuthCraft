// com/authcraft/bungee/command/BungeeLoginCommand.java
package com.authcraft.bungee.command;

import com.authcraft.core.AuthCraftCore;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

public class BungeeLoginCommand extends Command {

    private final AuthCraftCore core;

    public BungeeLoginCommand(AuthCraftCore core) {
        super("login", null, "l");
        this.core = core;
    }

    @Override
    public void execute(CommandSender sender, String[] args) {
        if (!(sender instanceof ProxiedPlayer player)) {
            sender.sendMessage(TextComponent.fromLegacyText("§cPlayers only."));
            return;
        }

        if (args.length != 1) {
            player.sendMessage(TextComponent.fromLegacyText(
                    "§eUsage: /login <password>"));
            return;
        }

        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "unknown";

        core.getAuthService()
                .login(player.getUniqueId(), player.getName(), args[0], ip)
                .thenAccept(result -> {
                    if (!result.isSuccessful()
                            && result.getStatus() !=
                            com.authcraft.core.model.AuthResult.Status.REQUIRES_2FA) {
                        player.sendMessage(TextComponent.fromLegacyText(result.getMessage()));
                    }
                })
                .exceptionally(ex -> {
                    player.sendMessage(TextComponent.fromLegacyText(
                            "§cLogin error: " + ex.getMessage()));
                    return null;
                });
    }
}