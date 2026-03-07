// com/authcraft/bungee/listener/BungeeChatListener.java
package com.authcraft.bungee.listener;

import com.authcraft.core.AuthCraftCore;

import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.event.ChatEvent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;

import java.util.Set;

public class BungeeChatListener implements Listener {

    private final AuthCraftCore core;

    private static final Set<String> ALLOWED_COMMANDS = Set.of(
            "/register", "/login", "/l", "/reg",
            "/2fa", "/changepassword", "/cp"
    );

    public BungeeChatListener(AuthCraftCore core) {
        this.core = core;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChat(ChatEvent event) {
        if (!(event.getSender() instanceof ProxiedPlayer player)) return;

        if (!core.isInLimbo(player.getUniqueId())) return;

        if (event.isCommand()) {
            String cmd = event.getMessage().split(" ")[0].toLowerCase();
            if (!ALLOWED_COMMANDS.contains(cmd)) {
                event.setCancelled(true);
                player.sendMessage(TextComponent.fromLegacyText(
                        "§cYou must authenticate first."
                ));
            }
        } else {
            event.setCancelled(true);
            player.sendMessage(TextComponent.fromLegacyText(
                    "§cYou must authenticate before chatting."
            ));
        }
    }
}