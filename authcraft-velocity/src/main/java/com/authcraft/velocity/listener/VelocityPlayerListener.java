// com/authcraft/velocity/listener/VelocityPlayerListener.java
package com.authcraft.velocity.listener;

import com.authcraft.core.AuthCraftCore;
import com.authcraft.security.SecurityChain;

import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;

import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.util.Set;

public class VelocityPlayerListener {

    private final AuthCraftCore core;
    private final SecurityChain securityChain;
    private static final LegacyComponentSerializer LEGACY =
            LegacyComponentSerializer.legacySection();

    private static final Set<String> ALLOWED_COMMANDS = Set.of(
            "/register", "/login", "/l", "/reg", "/2fa", "/changepassword", "/cp"
    );

    public VelocityPlayerListener(AuthCraftCore core, SecurityChain securityChain) {
        this.core = core;
        this.securityChain = securityChain;
    }

    @Subscribe(order = PostOrder.FIRST)
    public void onPreLogin(PreLoginEvent event) {
        String ip = event.getConnection().getRemoteAddress()
                .getAddress().getHostAddress();
        String username = event.getUsername();

        var result = securityChain.check(ip, username, null);
        if (!result.isAllowed()) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    LEGACY.deserialize(result.getKickReason())
            ));
        }
    }

    @Subscribe(order = PostOrder.NORMAL)
    public void onLogin(LoginEvent event) {
        Player player = event.getPlayer();
        String ip = player.getRemoteAddress().getAddress().getHostAddress();

        core.handlePlayerJoin(player.getUniqueId(), player.getUsername(), ip);
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        core.getAuthService().handleQuit(event.getPlayer().getUniqueId());
    }

    @Subscribe(order = PostOrder.FIRST)
    public void onChat(PlayerChatEvent event) {
        if (!core.isInLimbo(event.getPlayer().getUniqueId())) return;

        String message = event.getMessage();
        if (message.startsWith("/")) {
            String cmd = message.split(" ")[0].toLowerCase();
            if (!ALLOWED_COMMANDS.contains(cmd)) {
                event.setResult(PlayerChatEvent.ChatResult.denied());
                event.getPlayer().sendMessage(
                        LEGACY.deserialize("§cYou must authenticate first."));
            }
        } else {
            event.setResult(PlayerChatEvent.ChatResult.denied());
            event.getPlayer().sendMessage(
                    LEGACY.deserialize("§cYou must authenticate before chatting."));
        }
    }

    @Subscribe(order = PostOrder.FIRST)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        if (core.isInLimbo(event.getPlayer().getUniqueId())) {
            // Block server switching while in limbo
            // Allow initial connection only
            if (event.getPlayer().getCurrentServer().isPresent()) {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                event.getPlayer().sendMessage(
                        LEGACY.deserialize("§cYou must authenticate first."));
            }
        }
    }
}