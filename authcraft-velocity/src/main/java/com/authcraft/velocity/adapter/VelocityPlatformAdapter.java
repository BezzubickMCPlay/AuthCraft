package com.authcraft.velocity.adapter;

import com.authcraft.core.api.PlatformAdapter;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.title.Title;

import java.io.File;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class VelocityPlatformAdapter implements PlatformAdapter {

    private final ProxyServer server;
    private final Logger logger;
    private final File dataFolder;
    private final Object plugin;
    private final Map<Integer, ScheduledTask> tasks = new HashMap<>();
    private int taskCounter = 0;

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacySection();

    public VelocityPlatformAdapter(ProxyServer server, Logger logger, File dataFolder, Object plugin) {
        this.server = server;
        this.logger = logger;
        this.dataFolder = dataFolder;
        this.plugin = plugin;
    }

    private Optional<Player> getPlayer(UUID uuid) {
        return server.getPlayer(uuid);
    }

    @Override
    public void sendMessage(UUID playerUuid, String message) {
        getPlayer(playerUuid).ifPresent(p -> p.sendMessage(LEGACY.deserialize(message)));
    }

    @Override
    public void sendTitle(UUID playerUuid, String title, String subtitle, int fadeIn, int stay, int fadeOut) {
        getPlayer(playerUuid).ifPresent(p -> p.showTitle(Title.title(
                LEGACY.deserialize(title),
                LEGACY.deserialize(subtitle),
                Title.Times.times(
                        Duration.ofMillis(fadeIn * 50L),
                        Duration.ofMillis(stay * 50L),
                        Duration.ofMillis(fadeOut * 50L)
                )
        )));
    }

    @Override
    public void kickPlayer(UUID playerUuid, String reason) {
        getPlayer(playerUuid).ifPresent(p -> p.disconnect(LEGACY.deserialize(reason)));
    }

    @Override
    public boolean isPlayerOnline(UUID playerUuid) {
        return getPlayer(playerUuid).isPresent();
    }

    @Override
    public String getPlayerIp(UUID playerUuid) {
        return getPlayer(playerUuid)
                .map(p -> p.getRemoteAddress().getAddress().getHostAddress())
                .orElse("unknown");
    }

    @Override
    public String getPlayerName(UUID playerUuid) {
        return getPlayer(playerUuid)
                .map(Player::getUsername)
                .orElse("Unknown");
    }

    @Override
    public void setLimboState(UUID playerUuid, boolean limbo) {
        // Velocity: block server switching while in limbo
    }

    @Override
    public void setPermission(UUID playerUuid, String permission, boolean value) {
        // Velocity uses permission functions from LuckPerms or similar
    }

    @Override
    public boolean hasPermission(UUID playerUuid, String permission) {
        return getPlayer(playerUuid)
                .map(p -> p.hasPermission(permission))
                .orElse(false);
    }

    @Override
    public void runAsync(Runnable task) {
        server.getScheduler().buildTask(plugin, task).schedule();
    }

    @Override
    public void runSync(Runnable task) {
        // Velocity is fully async
        task.run();
    }

    @Override
    public int scheduleRepeating(Runnable task, long delayTicks, long periodTicks) {
        int id = ++taskCounter;
        ScheduledTask scheduled = server.getScheduler()
                .buildTask(plugin, task)
                .delay(delayTicks * 50, TimeUnit.MILLISECONDS)
                .repeat(periodTicks * 50, TimeUnit.MILLISECONDS)
                .schedule();
        tasks.put(id, scheduled);
        return id;
    }

    @Override
    public void cancelTask(int taskId) {
        ScheduledTask task = tasks.remove(taskId);
        if (task != null) task.cancel();
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
        return server.getBoundAddress().getPort();
    }

    @Override
    public Collection<UUID> getOnlinePlayers() {
        return server.getAllPlayers().stream()
                .map(Player::getUniqueId)
                .collect(Collectors.toList());
    }

    @Override
    public void broadcastPermission(String message, String permission) {
        Component component = LEGACY.deserialize(message);
        server.getAllPlayers().stream()
            .filter(p -> p.hasPermission(permission))
            .forEach(p -> p.sendMessage(component));
    }

    @Override
    public String getPlayerLocale(UUID playerUuid) {
        return getPlayer(playerUuid)
            .map(p -> p.getPlayerSettings().getLocale().getLanguage())
            .orElse(null);
    }
}
