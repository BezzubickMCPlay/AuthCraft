// com/authcraft/bukkit/integration/PlaceholderAPIIntegration.java
package com.authcraft.bukkit.integration;

import com.authcraft.core.AuthCraftCore;
import me.clip.placeholderapi.expansion.PlaceholderExpansion;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

/**
 * PlaceholderAPI expansion for AuthCraft.
 *
 * Placeholders:
 * %authcraft_authenticated% — true/false
 * %authcraft_role% — player's role
 * %authcraft_2fa% — 2FA method or NONE
 * %authcraft_last_login% — last login date
 * %authcraft_failed_attempts% — failed login attempts
 */
public class PlaceholderAPIIntegration extends PlaceholderExpansion {

    private final AuthCraftCore core;

    public PlaceholderAPIIntegration(AuthCraftCore core) {
        this.core = core;
    }

    @Override
    public @NotNull String getIdentifier() {
        return "authcraft";
    }

    @Override
    public @NotNull String getAuthor() {
        return "AuthCraft Team";
    }

    @Override
    public @NotNull String getVersion() {
        return "1.0.0";
    }

    @Override
    public boolean persist() {
        return true; // Don't unregister on reload
    }

    @Override
    public String onPlaceholderRequest(Player player, @NotNull String params) {
        if (player == null) return "";

        var uuid = player.getUniqueId();

        return switch (params.toLowerCase()) {
            case "authenticated" ->
                    String.valueOf(core.isAuthenticated(uuid));
            case "in_limbo" ->
                    String.valueOf(core.isInLimbo(uuid));
            case "role" -> {
                var acc = core.getStorage().getAccount(uuid).join();
                yield acc.map(a -> a.getRole()).orElse("guest");
            }
            case "2fa" -> {
                var acc = core.getStorage().getAccount(uuid).join();
                yield acc.map(a -> a.getTwoFactorMethod().name())
                        .orElse("NONE");
            }
            case "last_login" -> {
                var acc = core.getStorage().getAccount(uuid).join();
                yield acc.map(a -> a.getLastLoginDate() != null
                        ? a.getLastLoginDate().toString() : "Never")
                        .orElse("Never");
            }
            case "failed_attempts" -> {
                var acc = core.getStorage().getAccount(uuid).join();
                yield acc.map(a ->
                        String.valueOf(a.getFailedLoginAttempts()))
                        .orElse("0");
            }
            case "registered" -> {
                var acc = core.getStorage().getAccount(uuid).join();
                yield acc.map(a -> a.getCreatedAt().toString())
                        .orElse("Not registered");
            }
            default -> null;
        };
    }
}