// com/authcraft/core/service/RoleService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Role;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import org.yaml.snakeyaml.Yaml;

/**
 * Loads roles from roles.yml and manages role assignments.
 */
public class RoleService {

    private final PlatformAdapter platform;
    private final AuthCraftConfig config;
    private final Logger logger;

    private final Map<String, Role> roles;
    private String defaultRole;

    public RoleService(PlatformAdapter platform, AuthCraftConfig config) {
        this.platform = platform;
        this.config = config;
        this.logger = platform.getLogger();
        this.roles = new ConcurrentHashMap<>();
        this.defaultRole = "guest";
        loadRoles();
    }

    @SuppressWarnings("unchecked")
    public void loadRoles() {
        roles.clear();

        File rolesFile = new File(platform.getDataFolder(), "roles.yml");
        if (!rolesFile.exists()) {
            createDefaultRolesFile(rolesFile);
        }

        try (InputStream is = new FileInputStream(rolesFile)) {
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(is);

            if (data == null) {
                logger.warning("[AuthCraft] roles.yml is empty, "
                        + "using defaults");
                createDefaultRoles();
                return;
            }

            // Default role
            if (data.containsKey("default-role")) {
                defaultRole = (String) data.get("default-role");
            }

            // Roles
            Map<String, Map<String, Object>> rolesMap =
                    (Map<String, Map<String, Object>>) data.get("roles");

            if (rolesMap == null) {
                createDefaultRoles();
                return;
            }

            for (var entry : rolesMap.entrySet()) {
                String roleName = entry.getKey();
                Map<String, Object> roleData = entry.getValue();

                Role role = new Role();
                role.setName(roleName);
                role.setPermission(
                        (String) roleData.getOrDefault(
                                "permission", "authcraft." + roleName
                        )
                );
                role.setInherits(
                        (String) roleData.getOrDefault("inherits", null)
                );

                List<String> commands = (List<String>)
                        roleData.getOrDefault("commands", new ArrayList<>());
                role.setCommands(commands);

                Boolean requires2fa = (Boolean)
                        roleData.getOrDefault("requires-2fa", false);
                role.setRequires2fa(requires2fa != null && requires2fa);

                Integer priority = (Integer)
                        roleData.getOrDefault("priority", 0);
                role.setPriority(priority != null ? priority : 0);

                roles.put(roleName, role);
            }

            logger.info("[AuthCraft] Loaded " + roles.size()
                    + " roles from roles.yml");

        } catch (Exception e) {
            logger.warning("[AuthCraft] Failed to load roles.yml: "
                    + e.getMessage());
            createDefaultRoles();
        }
    }

    private void createDefaultRoles() {
        Role guest = new Role("guest", "authcraft.guest");
        guest.setCommands(Arrays.asList("help", "spawn"));
        guest.setRequires2fa(false);
        roles.put("guest", guest);

        Role player = new Role("player", "authcraft.player");
        player.setInherits("guest");
        player.setCommands(Arrays.asList("tpa", "home", "sethome"));
        player.setRequires2fa(false);
        roles.put("player", player);

        Role donator = new Role("donator", "authcraft.donator");
        donator.setInherits("player");
        donator.setCommands(Arrays.asList("kit donator", "fly"));
        donator.setRequires2fa(true);
        donator.setPriority(10);
        roles.put("donator", donator);

        Role moderator = new Role("moderator", "authcraft.moderator");
        moderator.setInherits("donator");
        moderator.setCommands(
                Arrays.asList("kick", "mute", "tempban", "vanish")
        );
        moderator.setRequires2fa(true);
        moderator.setPriority(50);
        roles.put("moderator", moderator);

        Role admin = new Role("admin", "authcraft.admin");
        admin.setInherits("moderator");
        admin.setCommands(
                Arrays.asList("ban", "unban", "setrole", "removerole",
                        "gamemode", "tp", "authcraft")
        );
        admin.setRequires2fa(true);
        admin.setPriority(100);
        roles.put("admin", admin);

        defaultRole = "guest";
    }

    private void createDefaultRolesFile(File file) {
        try {
            file.getParentFile().mkdirs();
            try (InputStream is = getClass().getClassLoader()
                    .getResourceAsStream("roles.yml")) {
                if (is != null) {
                    try (OutputStream os = new FileOutputStream(file)) {
                        is.transferTo(os);
                    }
                    return;
                }
            }
            // If no resource, write default
            try (PrintWriter writer = new PrintWriter(file)) {
                writer.println("default-role: guest");
                writer.println("roles:");
                writer.println("  guest:");
                writer.println("    permission: \"authcraft.guest\"");
                writer.println("    commands:");
                writer.println("      - \"help\"");
                writer.println("      - \"spawn\"");
                writer.println("    requires-2fa: false");
                writer.println("  admin:");
                writer.println("    permission: \"authcraft.admin\"");
                writer.println("    inherits: guest");
                writer.println("    commands:");
                writer.println("      - \"kick\"");
                writer.println("      - \"ban\"");
                writer.println("      - \"setrole\"");
                writer.println("      - \"removerole\"");
                writer.println("    requires-2fa: true");
            }
        } catch (IOException e) {
            logger.warning("[AuthCraft] Could not create roles.yml: "
                    + e.getMessage());
        }
    }

    // === Role Queries ===

    public Role getRole(String name) {
        return roles.get(name);
    }

    public String getDefaultRole() {
        return defaultRole;
    }

    public Map<String, Role> getAllRoles() {
        return Collections.unmodifiableMap(roles);
    }

    /**
     * Get all effective commands for a role
     * (including inherited).
     */
    public Set<String> getEffectiveCommands(String roleName) {
        Role role = roles.get(roleName);
        if (role == null) return Collections.emptySet();
        return role.getEffectiveCommands(roles);
    }

    /**
     * Check if a role requires 2FA.
     * Checks the role itself and all parent roles.
     */
    public boolean roleRequires2fa(String roleName) {
        Role role = roles.get(roleName);
        if (role == null) return false;
        if (role.isRequires2fa()) return true;
        if (role.getInherits() != null) {
            return roleRequires2fa(role.getInherits());
        }
        return false;
    }

    /**
     * Check if a role has permission to execute a command.
     */
    public boolean hasCommand(String roleName, String command) {
        return getEffectiveCommands(roleName).contains(command);
    }

    /**
     * Apply role permissions to a player.
     */
    public void applyRole(UUID uuid, String roleName) {
        Role role = roles.get(roleName);
        if (role == null) {
            logger.warning("[AuthCraft] Unknown role: " + roleName);
            return;
        }
        platform.setPermission(uuid, role.getPermission(), true);

        // Also set parent permissions
        if (role.getInherits() != null) {
            Role parent = roles.get(role.getInherits());
            if (parent != null) {
                platform.setPermission(uuid, parent.getPermission(), true);
            }
        }
    }

    /**
     * Remove role permissions from a player.
     */
    public void removeRole(UUID uuid, String roleName) {
        Role role = roles.get(roleName);
        if (role != null) {
            platform.setPermission(uuid, role.getPermission(), false);
        }
    }

    /**
     * Validate if role name is valid.
     */
    public boolean isValidRole(String roleName) {
        return roles.containsKey(roleName);
    }
}