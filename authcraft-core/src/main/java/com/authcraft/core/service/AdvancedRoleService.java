// com/authcraft/core/service/AdvancedRoleService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.Role;
import com.authcraft.core.model.AuditEvent;

import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Advanced Role Management Service.
 * 
 * Features:
 * - GUI-based role editor support
 * - Permission inheritance visualization
 * - Temporary roles with expiration
 * - Role purchase integration (donation)
 * - Role change notifications
 * - Role hierarchy management
 */
public class AdvancedRoleService {

    private final AuthCraftConfig config;
    private final PlatformAdapter platform;
    private final StorageProvider storage;
    private final AuditService auditService;
    private final MessageService messageService;
    private final Logger logger;

    // Role definitions cache
    private final Map<String, Role> roles = new ConcurrentHashMap<>();

    // Temporary role assignments (playerUuid -> list of temporary roles)
    private final Map<UUID, List<TemporaryRole>> temporaryRoles = new ConcurrentHashMap<>();

    // Role purchase configurations
    private final Map<String, RolePurchase> rolePurchases = new ConcurrentHashMap<>();

    // Pending role purchases (transaction ID -> purchase info)
    private final Map<String, PendingPurchase> pendingPurchases = new ConcurrentHashMap<>();

    // Role change listeners
    private final List<RoleChangeListener> listeners = new CopyOnWriteArrayList<>();

    // Background executor for cleanup
    private final ScheduledExecutorService executor;

    /**
     * Creates a new AdvancedRoleService.
     */
    public AdvancedRoleService(AuthCraftConfig config, PlatformAdapter platform,
                               StorageProvider storage, AuditService auditService,
                               MessageService messageService) {
        this.config = config;
        this.platform = platform;
        this.storage = storage;
        this.auditService = auditService;
        this.messageService = messageService;
        this.logger = platform.getLogger();
        this.executor = Executors.newScheduledThreadPool(1);
    }

    /**
     * Initialize the service and start background tasks.
     */
    public void initialize() {
        loadRoles();
        loadRolePurchases();
        startCleanupTask();
        logger.info("Advanced Role Service initialized with " + roles.size() + " roles");
    }

    /**
     * Shutdown the service.
     */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
        logger.info("Advanced Role Service shutdown complete");
    }

    // === Role Management ===

    /**
     * Load roles from storage.
     */
    private void loadRoles() {
        // Roles are loaded from roles.yml via the platform implementation
        // This method can be extended to load from database if needed
    }

    /**
     * Load role purchase configurations.
     */
    private void loadRolePurchases() {
        // Load purchase configurations from config
    }

    /**
     * Get a role by name.
     */
    public Optional<Role> getRole(String name) {
        return Optional.ofNullable(roles.get(name.toLowerCase()));
    }

    /**
     * Get all roles.
     */
    public Map<String, Role> getAllRoles() {
        return Collections.unmodifiableMap(roles);
    }

    /**
     * Create or update a role.
     */
    public RoleResult createOrUpdateRole(Role role) {
        // Validate role
        if (role.getName() == null || role.getName().isEmpty()) {
            return RoleResult.error("Role name cannot be empty");
        }

        // Check for circular inheritance
        if (role.getInherits() != null) {
            if (hasCircularInheritance(role.getName(), role.getInherits())) {
                return RoleResult.error("Circular inheritance detected");
            }
        }

        boolean isNew = !roles.containsKey(role.getName().toLowerCase());
        roles.put(role.getName().toLowerCase(), role);

        // Notify listeners
        notifyRoleChanged(role.getName(), isNew ? "created" : "updated");

        // Audit log
        auditService.logSystem(AuditEventType.ROLE_CHANGED,
            "Role " + (isNew ? "created" : "updated") + ": " + role.getName());

        logger.info("Role " + role.getName() + " " + (isNew ? "created" : "updated"));
        return RoleResult.success("Role " + (isNew ? "created" : "updated") + " successfully");
    }

    /**
     * Delete a role.
     */
    public RoleResult deleteRole(String name) {
        Role role = roles.remove(name.toLowerCase());
        if (role == null) {
            return RoleResult.error("Role not found");
        }

        // Check if any accounts have this role
        // This would require storage query - for now just log warning
        logger.warning("Role " + name + " deleted. Players with this role should be updated.");

        // Notify listeners
        notifyRoleChanged(name, "deleted");

        // Audit log
        auditService.logSystem(AuditEventType.ROLE_CHANGED, "Role deleted: " + name);

        return RoleResult.success("Role deleted successfully");
    }

    /**
     * Check for circular inheritance.
     */
    private boolean hasCircularInheritance(String roleName, String inheritsFrom) {
        Set<String> visited = new HashSet<>();
        visited.add(roleName.toLowerCase());

        String current = inheritsFrom.toLowerCase();
        while (current != null) {
            if (visited.contains(current)) {
                return true;
            }
            visited.add(current);

            Role parent = roles.get(current);
            if (parent == null) {
                break;
            }
            current = parent.getInherits() != null ? parent.getInherits().toLowerCase() : null;
        }

        return false;
    }

    // === Permission Inheritance ===

    /**
     * Get the inheritance chain for a role.
     */
    public List<String> getInheritanceChain(String roleName) {
        List<String> chain = new ArrayList<>();
        String current = roleName.toLowerCase();

        while (current != null) {
            Role role = roles.get(current);
            if (role == null) {
                break;
            }
            chain.add(current);
            current = role.getInherits() != null ? role.getInherits().toLowerCase() : null;
        }

        return chain;
    }

    /**
     * Get all effective permissions for a role.
     */
    public Set<String> getEffectivePermissions(String roleName) {
        Set<String> permissions = new HashSet<>();
        collectPermissions(roleName.toLowerCase(), permissions);
        return permissions;
    }

    private void collectPermissions(String roleName, Set<String> permissions) {
        Role role = roles.get(roleName);
        if (role == null) {
            return;
        }

        // Add role's own commands/permissions
        if (role.getCommands() != null) {
            permissions.addAll(role.getCommands());
        }

        // Add permission node
        if (role.getPermission() != null) {
            permissions.add(role.getPermission());
        }

        // Recursively collect from parent
        if (role.getInherits() != null) {
            collectPermissions(role.getInherits().toLowerCase(), permissions);
        }
    }

    /**
     * Build inheritance tree for visualization.
     */
    public InheritanceTree buildInheritanceTree() {
        InheritanceTree tree = new InheritanceTree();

        // Find root roles (roles that don't inherit from anything)
        List<String> roots = roles.values().stream()
            .filter(r -> r.getInherits() == null)
            .map(Role::getName)
            .collect(Collectors.toList());

        for (String root : roots) {
            tree.addRoot(buildTreeNode(root.toLowerCase()));
        }

        return tree;
    }

    private InheritanceTreeNode buildTreeNode(String roleName) {
        Role role = roles.get(roleName);
        if (role == null) {
            return null;
        }

        InheritanceTreeNode node = new InheritanceTreeNode(roleName, role);

        // Find children (roles that inherit from this role)
        for (Role r : roles.values()) {
            if (roleName.equalsIgnoreCase(r.getInherits())) {
                node.addChild(buildTreeNode(r.getName().toLowerCase()));
            }
        }

        return node;
    }

    // === Temporary Roles ===

    /**
     * Assign a temporary role to a player.
     */
    public RoleResult assignTemporaryRole(UUID playerUuid, String roleName, 
                                           long durationMillis, String reason) {
        Role role = roles.get(roleName.toLowerCase());
        if (role == null) {
            return RoleResult.error("Role not found");
        }

        long expiresAt = System.currentTimeMillis() + durationMillis;
        TemporaryRole tempRole = new TemporaryRole(
            playerUuid, roleName.toLowerCase(), expiresAt, reason
        );

        temporaryRoles.computeIfAbsent(playerUuid, k -> new ArrayList<>()).add(tempRole);

        // Assign the role to the account
        storage.getAccount(playerUuid).thenAccept(optAccount -> {
            optAccount.ifPresent(account -> {
                account.setRole(roleName);
                storage.saveAccount(account);
            });
        });

        // Notify player
        platform.runSync(() -> {
            if (platform.isPlayerOnline(playerUuid)) {
                String msg = messageService.getForPlayer(playerUuid,
                    "role.temporary.assigned", "role", roleName);
                platform.sendMessage(playerUuid, msg);
            }
        });

        // Audit log
        auditService.log(AuditEventType.ROLE_CHANGED, playerUuid, playerName(playerUuid),
            playerIp(playerUuid), "Temporary role assigned: " + roleName + " for " + formatDuration(durationMillis));

        logger.info("Temporary role " + roleName + " assigned to " + playerUuid + 
            " for " + formatDuration(durationMillis));

        return RoleResult.success("Temporary role assigned successfully");
    }

    /**
     * Remove a temporary role from a player.
     */
    public RoleResult removeTemporaryRole(UUID playerUuid, String roleName) {
        List<TemporaryRole> playerTempRoles = temporaryRoles.get(playerUuid);
        if (playerTempRoles == null) {
            return RoleResult.error("No temporary roles found for player");
        }

        boolean removed = playerTempRoles.removeIf(
            tr -> tr.getRoleName().equalsIgnoreCase(roleName)
        );

        if (!removed) {
            return RoleResult.error("Temporary role not found");
        }

        // Revert to default role
        storage.getAccount(playerUuid).thenAccept(optAccount -> {
            optAccount.ifPresent(account -> {
                account.setRole(config.getDefaultLanguage().equals("ru") ? "player" : "player");
                storage.saveAccount(account);
            });
        });

        // Notify player
        platform.runSync(() -> {
            if (platform.isPlayerOnline(playerUuid)) {
                platform.sendMessage(playerUuid, 
                    messageService.getForPlayer(playerUuid, "role.temporary.expired",
                        "role", roleName));
            }
        });

        // Audit log
        auditService.log(AuditEventType.ROLE_CHANGED, playerUuid, playerName(playerUuid),
            playerIp(playerUuid), "Temporary role removed: " + roleName);

        return RoleResult.success("Temporary role removed");
    }

    /**
     * Get all temporary roles for a player.
     */
    public List<TemporaryRole> getTemporaryRoles(UUID playerUuid) {
        return temporaryRoles.getOrDefault(playerUuid, Collections.emptyList());
    }

    /**
     * Check if a player has a specific temporary role.
     */
    public boolean hasTemporaryRole(UUID playerUuid, String roleName) {
        List<TemporaryRole> playerTempRoles = temporaryRoles.get(playerUuid);
        if (playerTempRoles == null) {
            return false;
        }

        return playerTempRoles.stream()
            .anyMatch(tr -> tr.getRoleName().equalsIgnoreCase(roleName) && !tr.isExpired());
    }

    // === Role Purchase (Donation Integration) ===

    /**
     * Configure a role for purchase.
     */
    public void configureRolePurchase(String roleName, double price, 
                                       String currency, int durationDays) {
        RolePurchase purchase = new RolePurchase(roleName, price, currency, durationDays);
        rolePurchases.put(roleName.toLowerCase(), purchase);
        logger.info("Role purchase configured: " + roleName + " for " + price + " " + currency);
    }

    /**
     * Get available roles for purchase.
     */
    public List<RolePurchase> getAvailablePurchases() {
        return new ArrayList<>(rolePurchases.values());
    }

    /**
     * Initiate a role purchase.
     */
    public PurchaseResult initiatePurchase(UUID playerUuid, String roleName) {
        RolePurchase purchase = rolePurchases.get(roleName.toLowerCase());
        if (purchase == null) {
            return PurchaseResult.error("Role not available for purchase");
        }

        // Generate transaction ID
        String transactionId = UUID.randomUUID().toString();

        PendingPurchase pending = new PendingPurchase(
            transactionId, playerUuid, roleName, purchase.getPrice(),
            System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(30) // 30 min timeout
        );

        pendingPurchases.put(transactionId, pending);

        return PurchaseResult.pending(transactionId, purchase);
    }

    /**
     * Complete a role purchase (called by payment processor).
     */
    public PurchaseResult completePurchase(String transactionId) {
        PendingPurchase pending = pendingPurchases.remove(transactionId);
        if (pending == null) {
            return PurchaseResult.error("Transaction not found");
        }

        if (pending.isExpired()) {
            return PurchaseResult.error("Transaction expired");
        }

        // Assign the role
        RolePurchase purchase = rolePurchases.get(pending.getRoleName().toLowerCase());
        if (purchase == null) {
            return PurchaseResult.error("Role no longer available");
        }

        long duration = purchase.getDurationDays() > 0 
            ? TimeUnit.DAYS.toMillis(purchase.getDurationDays()) 
            : Long.MAX_VALUE; // Permanent

        RoleResult result;
        if (purchase.getDurationDays() > 0) {
            result = assignTemporaryRole(pending.getPlayerUuid(), 
                pending.getRoleName(), duration, "Purchased");
        } else {
            // Permanent role assignment
            storage.getAccount(pending.getPlayerUuid()).thenAccept(optAccount -> {
                optAccount.ifPresent(account -> {
                    account.setRole(pending.getRoleName());
                    storage.saveAccount(account);
                });
            });
            result = RoleResult.success("Role purchased successfully");
        }

        if (!result.isSuccess()) {
            return PurchaseResult.error(result.getMessage());
        }

        // Notify player
        platform.runSync(() -> {
            if (platform.isPlayerOnline(pending.getPlayerUuid())) {
                platform.sendMessage(pending.getPlayerUuid(),
                    messageService.getForPlayer(pending.getPlayerUuid(), 
                        "role.purchase.success", "role", pending.getRoleName()));
            }
        });

        // Audit log
        auditService.log(AuditEventType.ROLE_CHANGED, pending.getPlayerUuid(),
            playerName(pending.getPlayerUuid()), playerIp(pending.getPlayerUuid()),
            "Role purchased: " + pending.getRoleName() + " for " + pending.getAmount());

        return PurchaseResult.success("Role purchased successfully", pending.getRoleName());
    }

    /**
     * Cancel a pending purchase.
     */
    public void cancelPurchase(String transactionId) {
        pendingPurchases.remove(transactionId);
    }

    // === Role Change Notifications ===

    /**
     * Add a role change listener.
     */
    public void addListener(RoleChangeListener listener) {
        listeners.add(listener);
    }

    /**
     * Remove a role change listener.
     */
    public void removeListener(RoleChangeListener listener) {
        listeners.remove(listener);
    }

    private void notifyRoleChanged(String roleName, String action) {
        for (RoleChangeListener listener : listeners) {
            try {
                listener.onRoleChanged(roleName, action);
            } catch (Exception e) {
                logger.warning("Error notifying role listener: " + e.getMessage());
            }
        }
    }

    private void notifyPlayerRoleChanged(UUID playerUuid, String oldRole, String newRole) {
        for (RoleChangeListener listener : listeners) {
            try {
                listener.onPlayerRoleChanged(playerUuid, oldRole, newRole);
            } catch (Exception e) {
                logger.warning("Error notifying role listener: " + e.getMessage());
            }
        }
    }

    // === Background Tasks ===

    private void startCleanupTask() {
        executor.scheduleAtFixedRate(this::cleanupExpiredRoles, 
            1, 1, TimeUnit.MINUTES);
    }

    private void cleanupExpiredRoles() {
        long now = System.currentTimeMillis();

        temporaryRoles.forEach((playerUuid, tempRoles) -> {
            Iterator<TemporaryRole> iter = tempRoles.iterator();
            while (iter.hasNext()) {
                TemporaryRole tr = iter.next();
                if (tr.isExpired()) {
                    iter.remove();

                    // Revert role
                    storage.getAccount(playerUuid).thenAccept(optAccount -> {
                        optAccount.ifPresent(account -> {
                            account.setRole("player");
                            storage.saveAccount(account);
                        });
                    });

                    // Notify player
                    platform.runSync(() -> {
                        if (platform.isPlayerOnline(playerUuid)) {
                            platform.sendMessage(playerUuid,
                                messageService.getForPlayer(playerUuid, 
                                    "role.temporary.expired", "role", tr.getRoleName()));
                        }
                    });

                    // Audit log
                    auditService.log(AuditEventType.ROLE_CHANGED, playerUuid,
                        playerName(playerUuid), playerIp(playerUuid),
                        "Temporary role expired: " + tr.getRoleName());

                    logger.info("Temporary role " + tr.getRoleName() + 
                        " expired for " + playerUuid);
                }
            }

            // Remove empty list
            if (tempRoles.isEmpty()) {
                temporaryRoles.remove(playerUuid);
            }
        });

        // Cleanup expired pending purchases
        pendingPurchases.entrySet().removeIf(e -> e.getValue().isExpired());
    }

    // === Utility Methods ===

    private String formatDuration(long millis) {
        long days = TimeUnit.MILLISECONDS.toDays(millis);
        long hours = TimeUnit.MILLISECONDS.toHours(millis) % 24;
        long minutes = TimeUnit.MILLISECONDS.toMinutes(millis) % 60;

        if (days > 0) {
            return days + "d " + hours + "h";
        } else if (hours > 0) {
            return hours + "h " + minutes + "m";
        } else {
            return minutes + "m";
        }
    }

    /**
     * Get a player's name, or "Unknown" if not available.
     */
    private String playerName(UUID playerUuid) {
        String name = platform.getPlayerName(playerUuid);
        return name != null ? name : "Unknown";
    }

    /**
     * Get a player's IP address, or "Unknown" if not available.
     */
    private String playerIp(UUID playerUuid) {
        String ip = platform.getPlayerIp(playerUuid);
        return ip != null ? ip : "Unknown";
    }

    // === Data Classes ===

    /**
     * Represents a temporary role assignment.
     */
    public static class TemporaryRole {
        private final UUID playerUuid;
        private final String roleName;
        private final long expiresAt;
        private final String reason;
        private final long assignedAt;

        public TemporaryRole(UUID playerUuid, String roleName, long expiresAt, String reason) {
            this.playerUuid = playerUuid;
            this.roleName = roleName;
            this.expiresAt = expiresAt;
            this.reason = reason;
            this.assignedAt = System.currentTimeMillis();
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getRoleName() { return roleName; }
        public long getExpiresAt() { return expiresAt; }
        public String getReason() { return reason; }
        public long getAssignedAt() { return assignedAt; }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }

        public long getRemainingMillis() {
            return Math.max(0, expiresAt - System.currentTimeMillis());
        }
    }

    /**
     * Represents a role purchase configuration.
     */
    public static class RolePurchase {
        private final String roleName;
        private final double price;
        private final String currency;
        private final int durationDays; // 0 = permanent
        private final String description;

        public RolePurchase(String roleName, double price, String currency, int durationDays) {
            this.roleName = roleName;
            this.price = price;
            this.currency = currency;
            this.durationDays = durationDays;
            this.description = durationDays > 0 
                ? roleName + " for " + durationDays + " days" 
                : roleName + " (permanent)";
        }

        public String getRoleName() { return roleName; }
        public double getPrice() { return price; }
        public String getCurrency() { return currency; }
        public int getDurationDays() { return durationDays; }
        public String getDescription() { return description; }
        public boolean isPermanent() { return durationDays == 0; }
    }

    /**
     * Represents a pending purchase.
     */
    public static class PendingPurchase {
        private final String transactionId;
        private final UUID playerUuid;
        private final String roleName;
        private final double amount;
        private final long expiresAt;

        public PendingPurchase(String transactionId, UUID playerUuid, 
                               String roleName, double amount, long expiresAt) {
            this.transactionId = transactionId;
            this.playerUuid = playerUuid;
            this.roleName = roleName;
            this.amount = amount;
            this.expiresAt = expiresAt;
        }

        public String getTransactionId() { return transactionId; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getRoleName() { return roleName; }
        public double getAmount() { return amount; }
        public long getExpiresAt() { return expiresAt; }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    /**
     * Inheritance tree node for visualization.
     */
    public static class InheritanceTreeNode {
        private final String name;
        private final Role role;
        private final List<InheritanceTreeNode> children;

        public InheritanceTreeNode(String name, Role role) {
            this.name = name;
            this.role = role;
            this.children = new ArrayList<>();
        }

        public String getName() { return name; }
        public Role getRole() { return role; }
        public List<InheritanceTreeNode> getChildren() { return children; }

        public void addChild(InheritanceTreeNode child) {
            if (child != null) {
                children.add(child);
            }
        }
    }

    /**
     * Inheritance tree container.
     */
    public static class InheritanceTree {
        private final List<InheritanceTreeNode> roots;

        public InheritanceTree() {
            this.roots = new ArrayList<>();
        }

        public List<InheritanceTreeNode> getRoots() { return roots; }

        public void addRoot(InheritanceTreeNode node) {
            if (node != null) {
                roots.add(node);
            }
        }
    }

    /**
     * Role operation result.
     */
    public static class RoleResult {
        private final boolean success;
        private final String message;

        private RoleResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public static RoleResult success(String message) {
            return new RoleResult(true, message);
        }

        public static RoleResult error(String message) {
            return new RoleResult(false, message);
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }

    /**
     * Purchase operation result.
     */
    public static class PurchaseResult {
        private final boolean success;
        private final boolean pending;
        private final String message;
        private final String transactionId;
        private final RolePurchase purchase;
        private final String roleName;

        private PurchaseResult(boolean success, boolean pending, String message,
                               String transactionId, RolePurchase purchase, String roleName) {
            this.success = success;
            this.pending = pending;
            this.message = message;
            this.transactionId = transactionId;
            this.purchase = purchase;
            this.roleName = roleName;
        }

        public static PurchaseResult success(String message, String roleName) {
            return new PurchaseResult(true, false, message, null, null, roleName);
        }

        public static PurchaseResult pending(String transactionId, RolePurchase purchase) {
            return new PurchaseResult(false, true, null, transactionId, purchase, null);
        }

        public static PurchaseResult error(String message) {
            return new PurchaseResult(false, false, message, null, null, null);
        }

        public boolean isSuccess() { return success; }
        public boolean isPending() { return pending; }
        public String getMessage() { return message; }
        public String getTransactionId() { return transactionId; }
        public RolePurchase getPurchase() { return purchase; }
        public String getRoleName() { return roleName; }
    }

    /**
     * Listener interface for role changes.
     */
    public interface RoleChangeListener {
        /**
         * Called when a role definition is changed.
         */
        void onRoleChanged(String roleName, String action);

        /**
         * Called when a player's role is changed.
         */
        void onPlayerRoleChanged(UUID playerUuid, String oldRole, String newRole);
    }
}
