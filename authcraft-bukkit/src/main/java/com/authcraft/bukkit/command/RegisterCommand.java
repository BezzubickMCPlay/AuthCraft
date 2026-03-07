// com/authcraft/bukkit/command/RegisterCommand.java
package com.authcraft.bukkit.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.service.MessageService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public class RegisterCommand implements CommandExecutor {

    private final AuthCraftCore core;
    private final MessageService msg;

    public RegisterCommand(AuthCraftCore core) {
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

        if (args.length != 2) {
            player.sendMessage(msg.get("register.usage"));
            return true;
        }

        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "unknown";

        core.getAuthService()
                .register(player.getUniqueId(), player.getName(),
                        args[0], args[1], ip)
                .thenAccept(result -> {
                    if (!result.isSuccessful()) {
                        player.sendMessage(result.getMessage());
                    }
                })
                .exceptionally(ex -> {
                    player.sendMessage(msg.get("error.generic"));
                    core.getPlatform().getLogger().warning(
                            "[AuthCraft] Register error: " + ex.getMessage());
                    return null;
                });

        return true;
    }
}