// com/authcraft/core/service/PasswordBlacklist.java
package com.authcraft.core.service;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Password blacklist with 10000+ common passwords.
 * Downloads from GitHub if local file doesn't exist.
 * Also supports Have I Been Pwned k-Anonymity API.
 */
public class PasswordBlacklist {

    private static final String BLACKLIST_URL =
            "https://raw.githubusercontent.com/danielmiessler/"
                    + "SecLists/master/Passwords/Common-Credentials/"
                    + "10-million-password-list-top-10000.txt";

    private static final String HIBP_API =
            "https://api.pwnedpasswords.com/range/";

    private final Set<String> blacklist;
    private final Logger logger;
    private final boolean hibpEnabled;

    public PasswordBlacklist(Logger logger, File dataFolder,
                             boolean enableHIBP) {
        this.logger = logger;
        this.hibpEnabled = enableHIBP;
        this.blacklist = new HashSet<>();

        // 1. Load built-in defaults
        loadBuiltinDefaults();

        // 2. Load from file
        File blacklistFile = new File(dataFolder, "password-blacklist.txt");
        if (blacklistFile.exists()) {
            loadFromFile(blacklistFile);
        } else {
            // Try to download
            downloadBlacklist(blacklistFile);
            if (blacklistFile.exists()) {
                loadFromFile(blacklistFile);
            }
        }

        logger.info("[AuthCraft] Password blacklist loaded: "
                + blacklist.size() + " entries"
                + (hibpEnabled ? " + HIBP API" : ""));
    }

    /**
     * Check if password is in the blacklist.
     */
    public boolean isBlacklisted(String password) {
        if (blacklist.contains(password.toLowerCase())) {
            return true;
        }

        // Check HIBP API (k-Anonymity — only first 5 chars of SHA-1 sent)
        if (hibpEnabled) {
            return checkHIBP(password);
        }

        return false;
    }

    /**
     * Check Have I Been Pwned API using k-Anonymity.
     * Only the first 5 characters of the SHA-1 hash are sent.
     */
    private boolean checkHIBP(String password) {
        try {
            String sha1 = sha1(password).toUpperCase();
            String prefix = sha1.substring(0, 5);
            String suffix = sha1.substring(5);

            URL url = new URL(HIBP_API + prefix);
            var conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestProperty("User-Agent", "AuthCraft-Plugin");

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        // Format: HASH_SUFFIX:COUNT
                        String[] parts = line.split(":");
                        if (parts[0].equals(suffix)) {
                            int count = Integer.parseInt(parts[1].trim());
                            return count > 0;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Network error — don't block login
        }
        return false;
    }

    private String sha1(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(
                    input.getBytes(StandardCharsets.UTF_8)
            );
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            return "";
        }
    }

    private void loadBuiltinDefaults() {
        // Top 100 most common passwords
        String[] defaults = {
                "123456", "password", "12345678", "qwerty", "123456789",
                "12345", "1234", "111111", "1234567", "dragon",
                "123123", "baseball", "abc123", "football", "monkey",
                "letmein", "shadow", "master", "666666", "qwertyuiop",
                "123321", "mustang", "1234567890", "michael", "654321",
                "superman", "1qaz2wsx", "7777777", "121212", "000000",
                "qazwsx", "123qwe", "killer", "trustno1", "jordan",
                "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
                "soccer", "harley", "batman", "andrew", "tigger",
                "sunshine", "iloveyou", "2000", "charlie", "robert",
                "thomas", "hockey", "ranger", "daniel", "starwars",
                "klaster", "112233", "george", "computer", "michelle",
                "jessica", "pepper", "1111", "zxcvbn", "555555",
                "11111111", "131313", "freedom", "777777", "pass",
                "maggie", "159753", "aaaaaa", "ginger", "princess",
                "joshua", "cheese", "amanda", "summer", "love",
                "ashley", "nicole", "chelsea", "biteme", "matthew",
                "access", "yankees", "987654321", "dallas", "austin",
                "thunder", "taylor", "matrix", "minecraft", "server",
                "admin", "administrator", "root", "test", "guest",
                "password1", "password123", "changeme", "welcome",
                "p@ssword", "passw0rd", "letmein1", "qwerty123",
                "1q2w3e4r", "default", "login", "notch", "herobrine",
                "creeper", "enderman", "steve", "alex"
        };
        for (String pwd : defaults) {
            blacklist.add(pwd.toLowerCase());
        }
    }

    private void loadFromFile(File file) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim().toLowerCase();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    blacklist.add(line);
                }
            }
        } catch (IOException e) {
            logger.warning("[AuthCraft] Error reading blacklist: "
                    + e.getMessage());
        }
    }

    private void downloadBlacklist(File target) {
        try {
            logger.info("[AuthCraft] Downloading password blacklist...");
            URL url = new URL(BLACKLIST_URL);
            var conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            if (conn.getResponseCode() == 200) {
                target.getParentFile().mkdirs();
                try (InputStream in = conn.getInputStream();
                     OutputStream out = new FileOutputStream(target)) {
                    in.transferTo(out);
                }
                logger.info("[AuthCraft] Blacklist downloaded: "
                        + target.getName());
            }
        } catch (Exception e) {
            logger.warning("[AuthCraft] Could not download blacklist: "
                    + e.getMessage() + ". Using built-in list.");
        }
    }

    public int size() {
        return blacklist.size();
    }
}