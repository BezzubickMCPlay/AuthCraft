package com.authcraft.bukkit.adapter;

import com.authcraft.core.api.PlatformAdapter;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

import java.io.File;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class BukkitPlatformAdapter implements PlatformAdapter {

    private final JavaPlugin plugin;

    public BukkitPlatformAdapter(JavaPlugin plugin) { this.plugin = plugin; }

    @Override public void sendMessage(UUID uuid, String message) {
        Player p = Bukkit.getPlayer(uuid);
        if (p != null && p.isOnline()) p.sendMessage(message);
    }

    @Override public void sendTitle(UUID uuid, String title, String subtitle, int fadeIn, int stay, int fadeOut) {
        Player p = Bukkit.getPlayer(uuid);
        if (p != null && p.isOnline()) VersionAdapter.sendTitle(p, title, subtitle, fadeIn, stay, fadeOut);
    }

    @Override public void kickPlayer(UUID uuid, String reason) {
        runSync(() -> { Player p = Bukkit.getPlayer(uuid); if (p != null) p.kickPlayer(reason); });
    }

    @Override public boolean isPlayerOnline(UUID uuid) {
        Player p = Bukkit.getPlayer(uuid); return p != null && p.isOnline();
    }

    @Override public String getPlayerIp(UUID uuid) {
        Player p = Bukkit.getPlayer(uuid);
        return (p != null && p.getAddress() != null) ? p.getAddress().getAddress().getHostAddress() : "unknown";
    }

    @Override public String getPlayerName(UUID uuid) {
        Player p = Bukkit.getPlayer(uuid); return p != null ? p.getName() : "Unknown";
    }

    @Override public void setLimboState(UUID uuid, boolean limbo) {
        Player p = Bukkit.getPlayer(uuid);
        if (p == null) return;
        if (limbo) {
            p.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, 1, false, false));
            p.addPotionEffect(new PotionEffect(VersionAdapter.getSlowEffect(), Integer.MAX_VALUE, 255, false, false));
            p.addPotionEffect(new PotionEffect(PotionEffectType.INVISIBILITY, Integer.MAX_VALUE, 1, false, false));
            p.setWalkSpeed(0); p.setFlySpeed(0);
            VersionAdapter.setInvulnerable(p, true);
        } else {
            p.removePotionEffect(PotionEffectType.BLINDNESS);
            p.removePotionEffect(VersionAdapter.getSlowEffect());
            p.removePotionEffect(PotionEffectType.INVISIBILITY);
            p.setWalkSpeed(0.2f); p.setFlySpeed(0.1f);
            VersionAdapter.setInvulnerable(p, false);
        }
    }

    @Override public void setPermission(UUID uuid, String perm, boolean val) {
        Player p = Bukkit.getPlayer(uuid);
        if (p != null) { var a = p.addAttachment(plugin); a.setPermission(perm, val); p.recalculatePermissions(); }
    }

    @Override public boolean hasPermission(UUID uuid, String perm) {
        Player p = Bukkit.getPlayer(uuid); return p != null && p.hasPermission(perm);
    }

    @Override public void runAsync(Runnable task) { Bukkit.getScheduler().runTaskAsynchronously(plugin, task); }

    @Override public void runSync(Runnable task) {
        if (Bukkit.isPrimaryThread()) task.run();
        else Bukkit.getScheduler().runTask(plugin, task);
    }

    @Override public int scheduleRepeating(Runnable task, long delay, long period) {
        return Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, task, delay, period).getTaskId();
    }

    @Override public void cancelTask(int taskId) { Bukkit.getScheduler().cancelTask(taskId); }
    @Override public Logger getLogger() { return plugin.getLogger(); }
    @Override public File getDataFolder() { return plugin.getDataFolder(); }
    @Override public int getServerPort() { return Bukkit.getPort(); }

    @Override public Collection<UUID> getOnlinePlayers() {
        return Bukkit.getOnlinePlayers().stream().map(Player::getUniqueId).collect(Collectors.toList());
    }

    @Override public void broadcastPermission(String message, String perm) {
        Bukkit.getOnlinePlayers().stream().filter(p -> p.hasPermission(perm)).forEach(p -> p.sendMessage(message));
        Bukkit.getConsoleSender().sendMessage(message);
    }

    @Override public String getPlayerLocale(UUID uuid) {
        Player p = Bukkit.getPlayer(uuid);
        if (p == null) return null;
        // Player.getLocale() is available since 1.12
        try {
            return p.getLocale();
        } catch (NoSuchMethodError e) {
            // Fallback for older versions - use server default
            return null;
        }
    }
}