// com/authcraft/bukkit/command/LoginCommand.java
package com.authcraft.bukkit.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.AuthResult;
import com.authcraft.core.service.MessageService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public class LoginCommand implements CommandExecutor {

    private final AuthCraftCore core;
    private final MessageService msg;

    public LoginCommand(AuthCraftCore core) {
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

        if (args.length != 1) {
            player.sendMessage(msg.get("login.usage"));
            return true;
        }

        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "unknown";

        core.getAuthService()
                .login(player.getUniqueId(), player.getName(), args[0], ip)
                .thenAccept(result -> {
                    if (!result.isSuccessful()
                            && result.getStatus() != AuthResult.Status.REQUIRES_2FA) {
                        player.sendMessage(result.getMessage());
                    }
                })
                .exceptionally(ex -> {
                    player.sendMessage(msg.get("error.generic"));
                    return null;
                });

        return true;
    }
}