// com/authcraft/security/SecurityChain.java
package com.authcraft.security;

import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.service.AuditService;

import java.util.*;
import java.util.logging.Logger;

/**
 * Chain of Responsibility that executes all security checks
 * before allowing a player connection.
 */
public class SecurityChain {

    private final AuthCraftConfig config;
    private final AntiBot antiBot;
    private final GeoIPFilter geoIPFilter;
    private final UnicodeSpoofDetector spoofDetector;
    private final AuditService auditService;
    private final Logger logger;

    // Cache of all known usernames for spoof checking
    private final Set<String> knownUsernames;

    public SecurityChain(AuthCraftConfig config,
                         AntiBot antiBot,
                         GeoIPFilter geoIPFilter,
                         UnicodeSpoofDetector spoofDetector,
                         AuditService auditService,
                         Logger logger) {
        this.config = config;
        this.antiBot = antiBot;
        this.geoIPFilter = geoIPFilter;
        this.spoofDetector = spoofDetector;
        this.auditService = auditService;
        this.logger = logger;
        this.knownUsernames = Collections.synchronizedSet(
                new HashSet<>()
        );
    }

    /**
     * Run full security chain on an incoming connection.
     * Returns null if allowed, or a kick reason if blocked.
     */
    public SecurityResult check(String ip, String username,
                                java.util.UUID uuid) {
        // 1. GeoIP filter
        GeoIPFilter.GeoCheckResult geoResult =
                geoIPFilter.checkIp(ip);
        if (!geoResult.isAllowed()) {
            auditService.log(
                    AuditEventType.IP_BLOCKED, uuid, username, ip,
                    "GeoIP blocked: " + geoResult.getCountryCode()
            );
            return SecurityResult.blocked(
                    "§cConnection from your region is not allowed."
            );
        }

        // 2. AntiBot check
        AntiBot.BotCheckResult botResult =
                antiBot.checkConnection(ip, username);
        if (!botResult.isAllowed()) {
            auditService.log(
                    AuditEventType.BOT_DETECTED, uuid, username, ip,
                    "Confidence: "
                            + String.format("%.2f", botResult.getConfidence())
                            + " Reasons: "
                            + String.join(", ", botResult.getReasons())
            );
            return SecurityResult.blocked(
                    "§cConnection rejected by anti-bot system."
            );
        }

        // 3. Unicode spoofing check
        UnicodeSpoofDetector.SpoofCheckResult spoofResult =
                spoofDetector.check(username, knownUsernames);
        if (!spoofResult.isSafe()) {
            auditService.log(
                    AuditEventType.UNICODE_SPOOF_DETECTED,
                    uuid, username, ip,
                    "Issues: "
                            + String.join(", ", spoofResult.getIssues())
                            + " Normalized: " + spoofResult.getNormalizedName()
            );
            return SecurityResult.blocked(
                    "§cSuspicious username detected. "
                            + "Please use a different name."
            );
        }

        // All checks passed
        knownUsernames.add(username);
        return SecurityResult.allowed(geoResult.getCountryCode());
    }

    /**
     * Add a username to the known list (for spoof checking).
     */
    public void registerUsername(String username) {
        knownUsernames.add(username);
    }

    /**
     * Load existing usernames from database.
     */
    public void loadUsernames(Collection<String> usernames) {
        knownUsernames.addAll(usernames);
    }

    public AntiBot getAntiBot() { return antiBot; }
    public GeoIPFilter getGeoIPFilter() { return geoIPFilter; }
    public UnicodeSpoofDetector getSpoofDetector() {
        return spoofDetector;
    }

    public static class SecurityResult {
        private final boolean allowed;
        private final String kickReason;
        private final String countryCode;

        private SecurityResult(boolean allowed, String kickReason,
                               String countryCode) {
            this.allowed = allowed;
            this.kickReason = kickReason;
            this.countryCode = countryCode;
        }

        public static SecurityResult allowed(String country) {
            return new SecurityResult(true, null, country);
        }

        public static SecurityResult blocked(String reason) {
            return new SecurityResult(false, reason, null);
        }

        public boolean isAllowed() { return allowed; }
        public String getKickReason() { return kickReason; }
        public String getCountryCode() { return countryCode; }
    }
}