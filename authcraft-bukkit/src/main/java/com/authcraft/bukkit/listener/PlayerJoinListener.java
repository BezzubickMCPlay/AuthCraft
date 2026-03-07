// com/authcraft/bukkit/listener/PlayerJoinListener.java
package com.authcraft.bukkit.listener;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.security.SecurityChain;

import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerLoginEvent;

public class PlayerJoinListener implements Listener {

    private final AuthCraftCore core;
    private final SecurityChain securityChain;

    public PlayerJoinListener(AuthCraftCore core,
                              SecurityChain securityChain) {
        this.core = core;
        this.securityChain = securityChain;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPlayerLogin(PlayerLoginEvent event) {
        Player player = event.getPlayer();
        String ip = event.getAddress().getHostAddress();
        String username = player.getName();

        // Run security chain
        SecurityChain.SecurityResult result =
                securityChain.check(ip, username, player.getUniqueId());

        if (!result.isAllowed()) {
            event.disallow(
                    PlayerLoginEvent.Result.KICK_OTHER,
                    result.getKickReason()
            );
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress()
                : "unknown";

        // Suppress join message until authenticated
        event.setJoinMessage(null);

        // Start auth flow
        core.handlePlayerJoin(
                player.getUniqueId(),
                player.getName(),
                ip
        );
    }
}