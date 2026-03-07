// com/authcraft/bukkit/command/LogoutCommand.java
package com.authcraft.bukkit.command;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.service.MessageService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.UUID;

public class LogoutCommand implements CommandExecutor {

    private final AuthCraftCore core;
    private final MessageService msg;

    public LogoutCommand(AuthCraftCore core) {
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

        // Check if player is authenticated
        if (!core.isAuthenticated(uuid)) {
            player.sendMessage(msg.get("logout.not-authenticated"));
            return true;
        }

        // Get IP for audit
        String ip = player.getAddress() != null 
            ? player.getAddress().getAddress().getHostAddress() 
            : "unknown";

        // Invalidate session
        core.getSessionService().invalidateAllSessions(uuid)
            .thenAccept(v -> {
                // Set player as not authenticated
                core.setAuthenticated(uuid, false);

                // Log audit event
                core.getAuditService().log(
                    AuditEventType.LOGOUT,
                    uuid,
                    player.getName(),
                    ip,
                    "Player logged out"
                ).exceptionally(ex -> null);

                // Kick player from server with logout message
                core.getPlatform().runSync(() -> {
                    // Use player's locale for the kick message
                    String kickMessage = msg.getForPlayer(uuid, "logout.kick");
                    // If message key is not found, use fallback
                    if (kickMessage.equals("logout.kick")) {
                        kickMessage = "§cYou have been logged out.\n§7Your session has been terminated.\n§eReconnect to log in again.";
                    }
                    player.kickPlayer(kickMessage);
                });
            })
            .exceptionally(ex -> {
                player.sendMessage(msg.get("error.generic"));
                return null;
            });

        return true;
    }
}
