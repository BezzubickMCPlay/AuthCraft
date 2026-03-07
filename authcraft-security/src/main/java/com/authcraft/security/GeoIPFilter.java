// com/authcraft/security/GeoIPFilter.java
package com.authcraft.security;

import com.authcraft.core.config.AuthCraftConfig;

import java.io.*;
import java.net.*;
import java.util.logging.Logger;

/**
 * GeoIP-based connection filtering using MaxMind GeoIP2.
 * Falls back to online API if local database unavailable.
 */
public class GeoIPFilter {

    private final AuthCraftConfig config;
    private final Logger logger;
    private Object geoIpReader; // com.maxmind.geoip2.DatabaseReader

    public GeoIPFilter(AuthCraftConfig config, Logger logger,
                       File dataFolder) {
        this.config = config;
        this.logger = logger;

        if (config.isGeoIpEnabled()) {
            initDatabase(dataFolder);
        }
    }

    private void initDatabase(File dataFolder) {
        File dbFile = new File(
                dataFolder, config.getGeoIpDatabasePath()
        );
        if (dbFile.exists()) {
            try {
                // Use reflection to avoid hard dependency
                Class<?> readerClass = Class.forName(
                        "com.maxmind.geoip2.DatabaseReader"
                );
                Class<?> builderClass = Class.forName(
                        "com.maxmind.geoip2.DatabaseReader$Builder"
                );
                Object builder = builderClass
                        .getConstructor(File.class)
                        .newInstance(dbFile);
                geoIpReader = builderClass
                        .getMethod("build")
                        .invoke(builder);
                logger.info("[AuthCraft] GeoIP database loaded: "
                        + dbFile.getName());
            } catch (Exception e) {
                logger.warning("[AuthCraft] Failed to load GeoIP DB: "
                        + e.getMessage()
                        + ". Will use online fallback.");
            }
        } else {
            logger.warning("[AuthCraft] GeoIP database not found: "
                    + dbFile.getAbsolutePath()
                    + ". Will use online fallback.");
        }
    }

    /**
     * Check if an IP is allowed by GeoIP rules.
     */
    public GeoCheckResult checkIp(String ipAddress) {
        if (!config.isGeoIpEnabled()) {
            return GeoCheckResult.allowed(null);
        }

        // Skip local addresses
        if (isLocalAddress(ipAddress)) {
            return GeoCheckResult.allowed("LOCAL");
        }

        String countryCode = lookupCountry(ipAddress);
        if (countryCode == null) {
            // Cannot determine — allow by default
            return GeoCheckResult.allowed("UNKNOWN");
        }

        boolean inList = config.getGeoIpCountries()
                .contains(countryCode);

        boolean allowed;
        if ("whitelist".equalsIgnoreCase(config.getGeoIpMode())) {
            allowed = inList;
        } else {
            // blacklist
            allowed = !inList;
        }

        if (allowed) {
            return GeoCheckResult.allowed(countryCode);
        } else {
            return GeoCheckResult.blocked(countryCode);
        }
    }

    private String lookupCountry(String ipAddress) {
        // Try local database first
        if (geoIpReader != null) {
            try {
                Class<?> readerClass = geoIpReader.getClass();
                java.lang.reflect.Method countryMethod =
                        readerClass.getMethod(
                                "country", InetAddress.class
                        );
                Object response = countryMethod.invoke(
                        geoIpReader, InetAddress.getByName(ipAddress)
                );
                Object country = response.getClass()
                        .getMethod("getCountry")
                        .invoke(response);
                return (String) country.getClass()
                        .getMethod("getIsoCode")
                        .invoke(country);
            } catch (Exception e) {
                // Fall through to online API
            }
        }

        // Online fallback
        return lookupOnline(ipAddress);
    }

    private String lookupOnline(String ipAddress) {
        try {
            // Use HTTPS to prevent MITM attacks on geo lookup
            URL url = new URL(
                "https://ip-api.com/json/" + ipAddress
                + "?fields=countryCode"
            );
            HttpURLConnection conn =
                (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    String response = reader.readLine();
                    // Simple JSON parsing
                    int idx = response.indexOf("\"countryCode\":\"");
                    if (idx >= 0) {
                        int start = idx + 15;
                        int end = response.indexOf("\"", start);
                        return response.substring(start, end);
                    }
                }
            }
        } catch (Exception e) {
            logger.warning("[AuthCraft] GeoIP online lookup failed: "
                    + e.getMessage());
        }
        return null;
    }

    private boolean isLocalAddress(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isLoopbackAddress()
                    || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress();
        } catch (Exception e) {
            return false;
        }
    }

    public static class GeoCheckResult {
        private final boolean allowed;
        private final String countryCode;

        private GeoCheckResult(boolean allowed, String countryCode) {
            this.allowed = allowed;
            this.countryCode = countryCode;
        }

        public static GeoCheckResult allowed(String country) {
            return new GeoCheckResult(true, country);
        }

        public static GeoCheckResult blocked(String country) {
            return new GeoCheckResult(false, country);
        }

        public boolean isAllowed() { return allowed; }
        public String getCountryCode() { return countryCode; }
    }
}