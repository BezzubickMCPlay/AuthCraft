// com/authcraft/bungee/command/BungeeChangePasswordCommand.java
package com.authcraft.bungee.command;

import com.authcraft.core.AuthCraftCore;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

public class BungeeChangePasswordCommand extends Command {

    private final AuthCraftCore core;

    public BungeeChangePasswordCommand(AuthCraftCore core) {
        super("changepassword", null, "cp", "passwd");
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
                    "§eUsage: /changepassword <old> <new>"));
            return;
        }

        core.getAuthService()
                .changePassword(player.getUniqueId(), args[0], args[1])
                .thenAccept(result ->
                        player.sendMessage(TextComponent.fromLegacyText(result.getMessage()))
                )
                .exceptionally(ex -> {
                    player.sendMessage(TextComponent.fromLegacyText(
                            "§cError: " + ex.getMessage()));
                    return null;
                });
    }
}