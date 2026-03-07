// com/authcraft/bukkit/adapter/VersionAdapter.java
package com.authcraft.bukkit.adapter;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.logging.Logger;

/**
 * Handles API differences between Minecraft 1.8 and 1.21.
 * Uses reflection for methods that don't exist in older versions.
 */
public class VersionAdapter {

    private static final int MAJOR_VERSION;
    private static final int MINOR_VERSION;

    // Cached reflection lookups
    private static Method sendTitleMethod;
    private static Method setInvulnerableMethod;
    private static boolean hasNativeTitles;
    private static boolean hasPlayerPickupEvent;
    private static PotionEffectType slowEffect;

    static {
        // Parse version: "1.20.1-R0.1-SNAPSHOT" -> major=1, minor=20
        String version = Bukkit.getBukkitVersion();
        String[] parts = version.split("[.-]");
        MAJOR_VERSION = Integer.parseInt(parts[0]);
        MINOR_VERSION = Integer.parseInt(parts[1]);

        // Determine available APIs
        hasNativeTitles = MINOR_VERSION >= 9; // sendTitle(String,String,int,int,int)
        hasPlayerPickupEvent = MINOR_VERSION >= 12;

        // PotionEffectType.SLOW was renamed to SLOWNESS in some versions
        slowEffect = resolveSlowEffect();

        // setInvulnerable added in 1.9
        if (MINOR_VERSION >= 9) {
            try {
                setInvulnerableMethod = Player.class.getMethod(
                        "setInvulnerable", boolean.class
                );
            } catch (NoSuchMethodException ignored) {}
        }

        Logger.getLogger("AuthCraft").info(
                "[AuthCraft] Detected Minecraft " + MAJOR_VERSION + "." + MINOR_VERSION
                        + " | Titles: " + hasNativeTitles
                        + " | Invulnerable: " + (setInvulnerableMethod != null)
                        + " | PickupEvent: " + hasPlayerPickupEvent
        );
    }

    /**
     * Send title to player, compatible with 1.8+.
     */
    public static void sendTitle(Player player, String title, String subtitle,
        int fadeIn, int stay, int fadeOut) {
        if (hasNativeTitles) {
            try {
                // Modern API (1.17+) uses sendTitle with Title object
                // Older API (1.8-1.16) uses sendTitle with 5 parameters
                try {
                    // Try modern API first (1.17+)
                    player.sendTitle(title, subtitle);
                } catch (NoSuchMethodError e1) {
                    // Try older API (1.8-1.16)
                    player.sendTitle(title, subtitle, fadeIn, stay, fadeOut);
                }
                return;
            } catch (NoSuchMethodError e) {
                // Fallback
            }
        }
    
        // 1.8 fallback using NMS/Reflection
        sendTitle18(player, title, subtitle, fadeIn, stay, fadeOut);
    }

    /**
     * 1.8 title sending via NMS reflection.
     */
    @SuppressWarnings("all")
    private static void sendTitle18(Player player, String title, String subtitle,
                                    int fadeIn, int stay, int fadeOut) {
        try {
            String nmsVersion = Bukkit.getServer().getClass()
                    .getPackage().getName().split("\\.")[3];

            Class<?> packetClass = Class.forName(
                    "net.minecraft.server." + nmsVersion + ".PacketPlayOutTitle"
            );
            Class<?> chatClass = Class.forName(
                    "net.minecraft.server." + nmsVersion + ".IChatBaseComponent"
            );
            Class<?> serializerClass = Class.forName(
                    "net.minecraft.server." + nmsVersion
                            + ".IChatBaseComponent$ChatSerializer"
            );
            Class<?> enumClass = Class.forName(
                    "net.minecraft.server." + nmsVersion
                            + ".PacketPlayOutTitle$EnumTitleAction"
            );

            // Timing packet
            Constructor<?> timingConstructor = packetClass.getConstructor(
                    int.class, int.class, int.class
            );
            Object timingPacket = timingConstructor.newInstance(
                    fadeIn, stay, fadeOut
            );
            sendPacket(player, timingPacket, nmsVersion);

            // Title packet
            if (title != null && !title.isEmpty()) {
                Method fromJson = serializerClass.getMethod("a", String.class);
                Object chatTitle = fromJson.invoke(null,
                        "{\"text\":\"" + escapeJson(title) + "\"}");

                Object[] enumValues = enumClass.getEnumConstants();
                Object titleEnum = enumValues[0]; // TITLE

                Constructor<?> titleConstructor = packetClass.getConstructor(
                        enumClass, chatClass
                );
                Object titlePacket = titleConstructor.newInstance(
                        titleEnum, chatTitle
                );
                sendPacket(player, titlePacket, nmsVersion);
            }

            // Subtitle packet
            if (subtitle != null && !subtitle.isEmpty()) {
                Method fromJson = serializerClass.getMethod("a", String.class);
                Object chatSubtitle = fromJson.invoke(null,
                        "{\"text\":\"" + escapeJson(subtitle) + "\"}");

                Object[] enumValues = enumClass.getEnumConstants();
                Object subtitleEnum = enumValues[1]; // SUBTITLE

                Constructor<?> subtitleConstructor = packetClass.getConstructor(
                        enumClass, chatClass
                );
                Object subtitlePacket = subtitleConstructor.newInstance(
                        subtitleEnum, chatSubtitle
                );
                sendPacket(player, subtitlePacket, nmsVersion);
            }

        } catch (Exception e) {
            // Last resort: send as chat message
            if (title != null) player.sendMessage(title);
            if (subtitle != null) player.sendMessage(subtitle);
        }
    }

    private static void sendPacket(Player player, Object packet,
                                   String nmsVersion) throws Exception {
        Method getHandle = player.getClass().getMethod("getHandle");
        Object entityPlayer = getHandle.invoke(player);

        Object connection = entityPlayer.getClass()
                .getField("playerConnection").get(entityPlayer);

        Method sendPacket = connection.getClass()
                .getMethod("sendPacket",
                        Class.forName("net.minecraft.server." + nmsVersion + ".Packet")
                );
        sendPacket.invoke(connection, packet);
    }

    /**
     * Set player invulnerable, compatible with 1.8+.
     */
    public static void setInvulnerable(Player player, boolean invulnerable) {
        if (setInvulnerableMethod != null) {
            try {
                setInvulnerableMethod.invoke(player, invulnerable);
                return;
            } catch (Exception ignored) {}
        }

        // 1.8 fallback: use max health trick or just ignore
        if (invulnerable) {
            player.addPotionEffect(new PotionEffect(
                    PotionEffectType.DAMAGE_RESISTANCE,
                    Integer.MAX_VALUE, 255, false, false
            ));
        } else {
            player.removePotionEffect(PotionEffectType.DAMAGE_RESISTANCE);
        }
    }

    /**
     * Get the correct SLOW/SLOWNESS PotionEffectType.
     */
    public static PotionEffectType getSlowEffect() {
        return slowEffect;
    }

    private static PotionEffectType resolveSlowEffect() {
        try {
            // Try SLOW first (older versions)
            return (PotionEffectType) PotionEffectType.class
                    .getField("SLOW").get(null);
        } catch (Exception e1) {
            try {
                // Try SLOWNESS (newer versions)
                return (PotionEffectType) PotionEffectType.class
                        .getField("SLOWNESS").get(null);
            } catch (Exception e2) {
                return PotionEffectType.getByName("SLOW");
            }
        }
    }

    /**
     * Check if we have the PlayerAttemptPickupItemEvent.
     */
    public static boolean hasPickupEvent() {
        return hasPlayerPickupEvent;
    }

    public static int getMinorVersion() {
        return MINOR_VERSION;
    }

    public static boolean isAtLeast(int minor) {
        return MINOR_VERSION >= minor;
    }

    private static String escapeJson(String text) {
        return text.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n");
    }
}