// com/authcraft/bukkit/listener/ChatListener.java
package com.authcraft.bukkit.listener;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.service.MessageService;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;

import java.util.Set;

public class ChatListener implements Listener {

    private final AuthCraftCore core;
    private final MessageService msg;

    private static final Set<String> ALLOWED_COMMANDS = Set.of(
            "/register", "/login", "/l", "/reg",
            "/2fa", "/changepassword", "/cp"
    );

    public ChatListener(AuthCraftCore core) {
        this.core = core;
        this.msg = core.getMessageService();
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChat(AsyncPlayerChatEvent event) {
        if (core.isInLimbo(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(msg.get("limbo.must-auth-chat"));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!core.isInLimbo(event.getPlayer().getUniqueId())) return;

        String cmd = event.getMessage().split(" ")[0].toLowerCase();
        if (!ALLOWED_COMMANDS.contains(cmd)) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(msg.get("limbo.must-auth-command"));
        }
    }
}