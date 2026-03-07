package com.authcraft.bungee.adapter;

import com.authcraft.core.api.PlatformAdapter;
import net.md_5.bungee.api.ChatMessageType;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.Title;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Plugin;

import java.io.File;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class BungeePlatformAdapter implements PlatformAdapter {

    private final Plugin plugin;
    private final Logger logger;
    private final File dataFolder;
    private final Map<Integer, Integer> taskIds = new HashMap<>();
    private int taskCounter = 0;

    public BungeePlatformAdapter(Plugin plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.dataFolder = plugin.getDataFolder();
    }

    @Override
    public void sendMessage(UUID playerUuid, String message) {
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(playerUuid);
        if (player != null) {
            player.sendMessage(TextComponent.fromLegacyText(message));
        }
    }

    @Override
    public void sendTitle(UUID playerUuid, String title, String subtitle, int fadeIn, int stay, int fadeOut) {
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(playerUuid);
        if (player != null) {
            Title titleObj = ProxyServer.getInstance().createTitle()
                    .title(TextComponent.fromLegacyText(title))
                    .subTitle(TextComponent.fromLegacyText(subtitle))
                    .fadeIn(fadeIn)
                    .stay(stay)
                    .fadeOut(fadeOut);
            player.sendTitle(titleObj);
        }
    }

    @Override
    public void kickPlayer(UUID playerUuid, String reason) {
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(playerUuid);
        if (player != null) {
            player.disconnect(TextComponent.fromLegacyText(reason));
        }
    }

    @Override
    public boolean isPlayerOnline(UUID playerUuid) {
        return ProxyServer.getInstance().getPlayer(playerUuid) != null;
    }

    @Override
    public String getPlayerIp(UUID playerUuid) {
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(playerUuid);
        if (player != null && player.getSocketAddress() != null) {
            return ((java.net.InetSocketAddress) player.getSocketAddress()).getAddress().getHostAddress();
        }
        return "unknown";
    }

    @Override
    public String getPlayerName(UUID playerUuid) {
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(playerUuid);
        return player != null ? player.getName() : "Unknown";
    }

    @Override
    public void setLimboState(UUID playerUuid, boolean limbo) {
        // BungeeCord doesn't handle limbo state directly
    }

    @Override
    public void setPermission(UUID playerUuid, String permission, boolean value) {
        // BungeeCord doesn't handle permissions directly
    }

    @Override
    public boolean hasPermission(UUID playerUuid, String permission) {
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(playerUuid);
        return player != null && player.hasPermission(permission);
    }

    @Override
    public void runAsync(Runnable task) {
        ProxyServer.getInstance().getScheduler().runAsync(plugin, task);
    }

    @Override
    public void runSync(Runnable task) {
        ProxyServer.getInstance().getScheduler().schedule(plugin, task, 0, TimeUnit.MILLISECONDS);
    }

    @Override
    public int scheduleRepeating(Runnable task, long delayTicks, long periodTicks) {
        int id = ++taskCounter;
        long delayMs = delayTicks * 50;
        long periodMs = periodTicks * 50;
        int scheduledId = ProxyServer.getInstance().getScheduler().schedule(plugin, task, delayMs, periodMs, TimeUnit.MILLISECONDS).getId();
        taskIds.put(id, scheduledId);
        return id;
    }

    @Override
    public void cancelTask(int taskId) {
        Integer scheduledId = taskIds.remove(taskId);
        if (scheduledId != null) {
            ProxyServer.getInstance().getScheduler().cancel(scheduledId);
        }
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    @Override
    public File getDataFolder() {
        return dataFolder;
    }

    @Override
    public int getServerPort() {
        return ProxyServer.getInstance().getConfig().getListeners().iterator().next().getHost().getPort();
    }

    @Override
    public Collection<UUID> getOnlinePlayers() {
        return ProxyServer.getInstance().getPlayers().stream()
                .map(ProxiedPlayer::getUniqueId)
                .collect(Collectors.toList());
    }

    @Override
    public void broadcastPermission(String message, String permission) {
        TextComponent component = new TextComponent(message);
        ProxyServer.getInstance().getPlayers().stream()
            .filter(p -> p.hasPermission(permission))
            .forEach(p -> p.sendMessage(component));
    }

    @Override
    public String getPlayerLocale(UUID playerUuid) {
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(playerUuid);
        if (player != null) {
            // BungeeCord uses getLocale() which returns Locale object
            java.util.Locale locale = player.getLocale();
            return locale != null ? locale.getLanguage() : null;
        }
        return null;
    }
}
