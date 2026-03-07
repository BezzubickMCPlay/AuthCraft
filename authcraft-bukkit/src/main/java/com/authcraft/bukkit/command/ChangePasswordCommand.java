// com/authcraft/bukkit/command/ChangePasswordCommand.java
package com.authcraft.bukkit.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.service.MessageService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public class ChangePasswordCommand implements CommandExecutor {

    private final AuthCraftCore core;
    private final MessageService msg;

    public ChangePasswordCommand(AuthCraftCore core) {
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
            player.sendMessage(msg.get("password.change-usage"));
            return true;
        }

        core.getAuthService()
                .changePassword(player.getUniqueId(), args[0], args[1])
                .thenAccept(result -> player.sendMessage(result.getMessage()))
                .exceptionally(ex -> {
                    player.sendMessage(msg.get("error.generic"));
                    return null;
                });

        return true;
    }
}