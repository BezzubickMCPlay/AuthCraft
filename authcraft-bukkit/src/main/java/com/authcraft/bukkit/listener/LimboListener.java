// com/authcraft/bukkit/listener/LimboListener.java
package com.authcraft.bukkit.listener;

import com.authcraft.bukkit.adapter.VersionAdapter;
import com.authcraft.core.AuthCraftCore;
import com.authcraft.core.config.AuthCraftConfig;

import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.*;

public class LimboListener implements Listener {

    private final AuthCraftCore core;
    private final AuthCraftConfig config;

    public LimboListener(AuthCraftCore core, AuthCraftConfig config) {
        this.core = core;
        this.config = config;
    }

    private boolean isInLimbo(Player player) {
        return core.isInLimbo(player.getUniqueId());
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerMove(PlayerMoveEvent event) {
        if (!isInLimbo(event.getPlayer())) return;
        if (config.isLimboFreezeMovement()) {
            if (event.getTo() != null
                    && (event.getFrom().getBlockX() != event.getTo().getBlockX()
                    || event.getFrom().getBlockY() != event.getTo().getBlockY()
                    || event.getFrom().getBlockZ() != event.getTo().getBlockZ())) {
                event.setTo(event.getFrom());
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onBlockBreak(BlockBreakEvent event) {
        if (isInLimbo(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (isInLimbo(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onEntityDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player player) {
            if (isInLimbo(player)) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onEntityDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player player) {
            if (isInLimbo(player)) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerDropItem(PlayerDropItemEvent event) {
        if (isInLimbo(event.getPlayer())) event.setCancelled(true);
    }

    // Item pickup — version-safe
    // PlayerAttemptPickupItemEvent exists only in 1.12+
    // For 1.8-1.11, we use PlayerPickupItemEvent (deprecated but works)
    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerPickupItem(org.bukkit.event.player.PlayerPickupItemEvent event) {
        if (isInLimbo(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player) {
            if (isInLimbo(player)) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player) {
            if (isInLimbo(player)) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerInteract(PlayerInteractEvent event) {
        if (isInLimbo(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerCommandPreprocess(PlayerCommandPreprocessEvent event) {
        // Double-safety: also block commands here
        if (!isInLimbo(event.getPlayer())) return;

        String cmd = event.getMessage().split(" ")[0].toLowerCase();
        if (!cmd.equals("/register") && !cmd.equals("/reg")
                && !cmd.equals("/login") && !cmd.equals("/l")
                && !cmd.equals("/2fa") && !cmd.equals("/changepassword")
                && !cmd.equals("/cp")) {
            event.setCancelled(true);
            event.getPlayer().sendMessage("§cYou must authenticate first.");
        }
    }
}