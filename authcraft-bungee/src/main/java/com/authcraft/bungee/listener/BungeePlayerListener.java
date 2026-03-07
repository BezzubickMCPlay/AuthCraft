// com/authcraft/bungee/listener/BungeePlayerListener.java
package com.authcraft.bungee.listener;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.security.SecurityChain;

import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;

public class BungeePlayerListener implements Listener {

    private final AuthCraftCore core;
    private final SecurityChain securityChain;

    public BungeePlayerListener(AuthCraftCore core,
                                SecurityChain securityChain) {
        this.core = core;
        this.securityChain = securityChain;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(PreLoginEvent event) {
        String ip = event.getConnection().getAddress()
                .getAddress().getHostAddress();
        String username = event.getConnection().getName();

        SecurityChain.SecurityResult result =
                securityChain.check(ip, username, null);

        if (!result.isAllowed()) {
            event.setCancelled(true);
            event.setCancelReason(
                    TextComponent.fromLegacyText(result.getKickReason())
            );
        }
    }

    @EventHandler
    public void onPostLogin(PostLoginEvent event) {
        var player = event.getPlayer();
        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress()
                : "unknown";

        core.handlePlayerJoin(
                player.getUniqueId(), player.getName(), ip
        );
    }

    @EventHandler
    public void onPlayerDisconnect(PlayerDisconnectEvent event) {
        core.getAuthService().handleQuit(
                event.getPlayer().getUniqueId()
        );
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onServerConnect(ServerConnectEvent event) {
        // Block server switching while in limbo
        if (core.isInLimbo(event.getPlayer().getUniqueId())) {
            // Allow only if connecting to auth server
            // or if this is the initial connection
            if (event.getReason() != ServerConnectEvent.Reason.JOIN_PROXY) {
                event.setCancelled(true);
                event.getPlayer().sendMessage(
                        TextComponent.fromLegacyText(
                                "§cYou must authenticate first."
                        )
                );
            }
        }
    }
}