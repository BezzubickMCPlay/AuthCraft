// com/authcraft/bungee/command/BungeeRegisterCommand.java
package com.authcraft.bungee.command;

import com.authcraft.core.AuthCraftCore;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

public class BungeeRegisterCommand extends Command {

    private final AuthCraftCore core;

    public BungeeRegisterCommand(AuthCraftCore core) {
        super("register", null, "reg");
        this.core = core;
    }

    @Override
    public void execute(CommandSender sender, String[] args) {
        if (!(sender instanceof ProxiedPlayer player)) {
            sender.sendMessage(TextComponent.fromLegacyText("§cPlayers only."));
            return;
        }

        if (args.length != 2) {
            player.sendMessage(TextComponent.fromLegacyText(
                    "§eUsage: /register <password> <password>"));
            return;
        }

        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "unknown";

        core.getAuthService()
                .register(player.getUniqueId(), player.getName(), args[0], args[1], ip)
                .thenAccept(result -> {
                    if (!result.isSuccessful()) {
                        player.sendMessage(TextComponent.fromLegacyText(result.getMessage()));
                    }
                })
                .exceptionally(ex -> {
                    player.sendMessage(TextComponent.fromLegacyText(
                            "§cRegistration error: " + ex.getMessage()));
                    return null;
                });
    }
}