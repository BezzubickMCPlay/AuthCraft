// com/authcraft/bukkit/integration/VaultIntegration.java
package com.authcraft.bukkit.integration;

import com.authcraft.core.AuthCraftCore;
import net.milkbowl.vault.permission.Permission;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.RegisteredServiceProvider;

import java.util.UUID;
import java.util.logging.Logger;

/**
 * Vault integration for permission management.
 * Falls back to Bukkit permissions if Vault unavailable.
 */
public class VaultIntegration {

    private Permission vaultPermission;
    private boolean available;
    private final Logger logger;

    public VaultIntegration(Logger logger) {
        this.logger = logger;
        this.available = false;
        setup();
    }

    private void setup() {
        if (Bukkit.getPluginManager().getPlugin("Vault") == null) {
            logger.info("[AuthCraft] Vault not found. "
                    + "Using Bukkit permissions.");
            return;
        }

        try {
            RegisteredServiceProvider<Permission> rsp =
                    Bukkit.getServicesManager()
                            .getRegistration(Permission.class);
            if (rsp != null) {
                vaultPermission = rsp.getProvider();
                available = true;
                logger.info("[AuthCraft] Vault integration enabled: "
                        + vaultPermission.getName());
            }
        } catch (Exception e) {
            logger.warning("[AuthCraft] Vault setup failed: "
                    + e.getMessage());
        }
    }

    /**
     * Add permission to a player via Vault.
     */
    public void addPermission(Player player, String permission) {
        if (available && vaultPermission != null) {
            vaultPermission.playerAdd(null, player, permission);
        }
    }

    /**
     * Remove permission from a player via Vault.
     */
    public void removePermission(Player player, String permission) {
        if (available && vaultPermission != null) {
            vaultPermission.playerRemove(null, player, permission);
        }
    }

    /**
     * Add player to a Vault group.
     */
    public void addGroup(Player player, String group) {
        if (available && vaultPermission != null) {
            vaultPermission.playerAddGroup(null, player, group);
        }
    }

    /**
     * Remove player from a Vault group.
     */
    public void removeGroup(Player player, String group) {
        if (available && vaultPermission != null) {
            vaultPermission.playerRemoveGroup(null, player, group);
        }
    }

    public boolean isAvailable() { return available; }
}