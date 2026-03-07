// com/authcraft/core/service/MessageService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.config.AuthCraftConfig;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import org.yaml.snakeyaml.Yaml;

/**
 * Localization service loading messages from YAML files.
 */
public class MessageService {

    private final PlatformAdapter platform;
    private final AuthCraftConfig config;
    private final Logger logger;

    // language -> key -> message
    private final Map<String, Map<String, String>> messages;
    private String defaultLang;

    public MessageService(PlatformAdapter platform,
                          AuthCraftConfig config) {
        this.platform = platform;
        this.config = config;
        this.logger = platform.getLogger();
        this.messages = new ConcurrentHashMap<>();
        this.defaultLang = config.getDefaultLanguage();
        loadMessages();
    }

    @SuppressWarnings("unchecked")
    private void loadMessages() {
        for (String lang : config.getSupportedLanguages()) {
            File langFile = new File(
                platform.getDataFolder(),
                "messages_" + lang + ".yml"
            );

            if (!langFile.exists()) {
                extractDefault(lang, langFile);
            }

            if (langFile.exists()) {
                try (InputStream is = new FileInputStream(langFile)) {
                    Yaml yaml = new Yaml();
                    Map<String, Object> data = yaml.load(is);
                    Map<String, String> flatMap = new HashMap<>();
                    flattenYaml("", data, flatMap);
                    messages.put(lang, flatMap);
                    logger.info("[AuthCraft] Loaded language: " + lang
                        + " (" + flatMap.size() + " keys)");
                } catch (Exception e) {
                    logger.warning("[AuthCraft] Failed to load " + lang
                        + ": " + e.getMessage());
                }
            }
        }

        // Ensure default language exists
        if (!messages.containsKey(defaultLang)) {
            messages.put(defaultLang, getBuiltinMessages());
        }
    }

    @SuppressWarnings("unchecked")
    private void flattenYaml(String prefix,
                             Map<String, Object> map,
                             Map<String, String> result) {
        if (map == null) return;
        for (var entry : map.entrySet()) {
            String key = prefix.isEmpty()
                ? entry.getKey()
                : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map) {
                flattenYaml(key, (Map<String, Object>) value, result);
            } else if (value != null) {
                result.put(key, value.toString());
            }
        }
    }

    private void extractDefault(String lang, File target) {
        try (InputStream is = getClass().getClassLoader()
            .getResourceAsStream("messages_" + lang + ".yml")) {
            if (is != null) {
                target.getParentFile().mkdirs();
                try (OutputStream os = new FileOutputStream(target)) {
                    is.transferTo(os);
                }
            }
        } catch (IOException e) {
            // Ignore — will use built-in
        }
    }

    /**
     * Get a message by key in the default language.
     */
    public String get(String key) {
        return get(key, defaultLang);
    }

    /**
     * Get a message by key in a specific language.
     */
    public String get(String key, String lang) {
        Map<String, String> langMap = messages.getOrDefault(
            lang, messages.get(defaultLang)
        );
        if (langMap == null) return key;
        return langMap.getOrDefault(key,
            messages.getOrDefault(defaultLang, Collections.emptyMap())
                .getOrDefault(key, key)
        );
    }

    /**
     * Get a message with placeholders replaced.
     */
    public String get(String key, Map<String, String> placeholders) {
        String msg = get(key);
        for (var entry : placeholders.entrySet()) {
            msg = msg.replace("{" + entry.getKey() + "}",
                entry.getValue());
        }
        return msg;
    }

    private Map<String, String> getBuiltinMessages() {
        Map<String, String> m = new HashMap<>();
        m.put("auth.register", "§aRegister: /register <password> <password>");
        m.put("auth.login", "§eLogin: /login <password>");
        m.put("auth.success", "§aSuccessfully authenticated!");
        m.put("auth.wrong-password", "§cWrong password. {remaining} attempts remaining.");
        m.put("auth.locked", "§cAccount locked. Try in {time}.");
        m.put("auth.registered", "§aRegistration successful! Welcome!");
        m.put("auth.already-registered", "§cThis username is already registered.");
        m.put("auth.passwords-mismatch", "§cPasswords do not match.");
        m.put("auth.2fa-required", "§eEnter your 2FA code: /2fa <code>");
        m.put("auth.2fa-invalid", "§cInvalid 2FA code. {remaining} attempts remaining.");
        m.put("auth.2fa-enabled", "§a2FA enabled successfully!");
        m.put("auth.2fa-disabled", "§a2FA disabled.");
        m.put("auth.password-changed", "§aPassword changed successfully!");
        m.put("auth.weak-password", "§cPassword is too weak.");
        m.put("auth.too-many-accounts", "§cToo many accounts from this IP.");
        m.put("auth.not-authenticated", "§cYou must be logged in.");
        m.put("error.generic", "§cAn error occurred. Please try again.");
        return m;
    }

    public void reload() {
        messages.clear();
        loadMessages();
    }

    /**
     * Get a message with a single placeholder.
     */
    public String get(String key, String placeholder, String value) {
        return get(key).replace("{" + placeholder + "}", value);
    }

    /**
     * Get with two placeholders.
     */
    public String get(String key, String p1, String v1, String p2, String v2) {
        return get(key)
            .replace("{" + p1 + "}", v1)
            .replace("{" + p2 + "}", v2);
    }

    /**
     * Get with three placeholders.
     */
    public String get(String key, String p1, String v1,
                      String p2, String v2, String p3, String v3) {
        return get(key)
            .replace("{" + p1 + "}", v1)
            .replace("{" + p2 + "}", v2)
            .replace("{" + p3 + "}", v3);
    }

    /**
     * Send localized message to player.
     */
    public void send(UUID uuid, String key) {
        platform.sendMessage(uuid, get(key));
    }

    /**
     * Send localized message with placeholder.
     */
    public void send(UUID uuid, String key, String placeholder, String value) {
        platform.sendMessage(uuid, get(key, placeholder, value));
    }

    /**
     * Send localized message with map of placeholders.
     */
    public void send(UUID uuid, String key, Map<String, String> placeholders) {
        platform.sendMessage(uuid, get(key, placeholders));
    }

    /**
     * Send multiple lines (for multi-line messages).
     */
    public void sendMultiline(UUID uuid, String key) {
        String msg = get(key);
        for (String line : msg.split("\\n")) {
            platform.sendMessage(uuid, line);
        }
    }

    /**
     * Get a message in the player's preferred language.
     * Falls back to default language if player locale is not supported.
     */
    public String getForPlayer(UUID uuid, String key) {
        String locale = platform.getPlayerLocale(uuid);
        String lang = resolveLanguage(locale);
        return get(key, lang);
    }

    /**
     * Get a message with placeholders in the player's preferred language.
     */
    public String getForPlayer(UUID uuid, String key, Map<String, String> placeholders) {
        String locale = platform.getPlayerLocale(uuid);
        String lang = resolveLanguage(locale);
        String msg = get(key, lang);
        for (var entry : placeholders.entrySet()) {
            msg = msg.replace("{" + entry.getKey() + "}", entry.getValue());
        }
        return msg;
    }

    /**
     * Get a message with a single placeholder in the player's preferred language.
     */
    public String getForPlayer(UUID uuid, String key, String placeholder, String value) {
        String locale = platform.getPlayerLocale(uuid);
        String lang = resolveLanguage(locale);
        return get(key, lang).replace("{" + placeholder + "}", value);
    }

    /**
     * Resolve a locale string to a supported language.
     * Returns default language if locale is null or not supported.
     */
    public String resolveLanguage(String locale) {
        if (locale == null || locale.isEmpty()) {
            return defaultLang;
        }
        // Normalize to lowercase
        String normalized = locale.toLowerCase().replace("-", "_");
        
        // First, try exact match (for codes like "zh_cn", "zh_tw")
        if (messages.containsKey(normalized)) {
            return normalized;
        }
        
        // Try with underscore format (e.g., "zh_cn" from "zh-CN")
        if (normalized.contains("_")) {
            String[] parts = normalized.split("_");
            String fullCode = parts[0] + "_" + parts[1];
            if (messages.containsKey(fullCode)) {
                return fullCode;
            }
        }
        
        // Fallback: try just the language part (e.g., "en" from "en_US")
        String lang = normalized.contains("_") ? normalized.split("_")[0] : normalized;
        if (messages.containsKey(lang)) {
            return lang;
        }
        
        return defaultLang;
    }
}
