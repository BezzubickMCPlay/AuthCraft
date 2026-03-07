// com/authcraft/bukkit/listener/PlayerQuitListener.java
package com.authcraft.bukkit.listener;

import com.authcraft.core.AuthCraftCore;

import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerQuitEvent;

public class PlayerQuitListener implements Listener {

    private final AuthCraftCore core;

    public PlayerQuitListener(AuthCraftCore core) {
        this.core = core;
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        core.getAuthService().handleQuit(
                event.getPlayer().getUniqueId()
        );

        // Suppress quit message if not authenticated
        if (!core.isAuthenticated(
                event.getPlayer().getUniqueId())) {
            event.setQuitMessage(null);
        }
    }
}