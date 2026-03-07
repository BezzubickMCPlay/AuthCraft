// com/authcraft/security/AntiBot.java
package com.authcraft.security;

import com.authcraft.core.config.AuthCraftConfig;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * AntiBot with confidence-based detection and pattern analysis.
 */
public class AntiBot {

    private final AuthCraftConfig config;
    private final Logger logger;

    // IP -> list of connection timestamps
    private final Map<String, List<Long>> connectionHistory;

    // Global connection counter per second
    private final AtomicInteger globalConnectionsThisSecond;
    private final AtomicLong lastSecondTimestamp;

    // Attack mode state
    private volatile boolean attackMode;
    private volatile long attackModeActivatedAt;

    // Known bot patterns
    private static final List<Pattern> BOT_NAME_PATTERNS = List.of(
            Pattern.compile("^Bot\\d+$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^Player_\\d{4,}$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^xXx_.*_xXx$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^[a-zA-Z]{1,3}\\d{5,}$"),
            Pattern.compile("^test\\d+$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^user\\d+$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^hack(er)?\\d*$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("^\\d{8,}$"),
            Pattern.compile("^[a-z]{16}$"), // Random 16-char lowercase
            Pattern.compile("^.{1,2}$") // Too short names
    );

    // Blocked IPs
    private final Set<String> blockedIps;

    public AntiBot(AuthCraftConfig config, Logger logger) {
        this.config = config;
        this.logger = logger;
        this.connectionHistory = new ConcurrentHashMap<>();
        this.globalConnectionsThisSecond = new AtomicInteger(0);
        this.lastSecondTimestamp = new AtomicLong(
                System.currentTimeMillis() / 1000
        );
        this.attackMode = false;
        this.blockedIps = ConcurrentHashMap.newKeySet();
    }

    /**
     * Analyze connection and return confidence score
     * that this is a bot (0.0-1.0).
     * Returns -1 if IP is blocked entirely.
     */
    public BotCheckResult checkConnection(String ip, String username) {
        if (!config.isAntiBotEnabled()) {
            return BotCheckResult.allow();
        }

        if (blockedIps.contains(ip)) {
            return BotCheckResult.blocked("IP is temporarily blocked");
        }

        double confidence = 0.0;
        List<String> reasons = new ArrayList<>();

        // 1. IP rate check
        double ipRateScore = checkIpRate(ip);
        if (ipRateScore > 0) {
            confidence += ipRateScore * 0.4;
            reasons.add("High connection rate from IP");
        }

        // 2. Global rate check
        double globalRateScore = checkGlobalRate();
        if (globalRateScore > 0) {
            confidence += globalRateScore * 0.2;
            reasons.add("Global connection rate exceeded");
        }

        // 3. Name pattern analysis
        if (config.isAntiBotPatternAnalysis()) {
            double nameScore = analyzeNamePattern(username);
            if (nameScore > 0) {
                confidence += nameScore * 0.3;
                reasons.add("Suspicious name pattern");
            }
        }

        // 4. Attack mode multiplier
        if (attackMode) {
            confidence *= 1.5;
            reasons.add("Attack mode active");
        }

        confidence = Math.min(1.0, confidence);

        // Check threshold
        if (confidence >= config.getAntiBotConfidenceThreshold()) {
            // Block IP if very high confidence
            if (confidence >= 0.9) {
                blockedIps.add(ip);
                // Auto-unblock after 10 minutes
                scheduleUnblock(ip, 600_000);
            }
            return BotCheckResult.detected(confidence, reasons);
        }

        // Check if we should activate attack mode
        checkAttackMode();

        return BotCheckResult.allow();
    }

    private double checkIpRate(String ip) {
        long now = System.currentTimeMillis();
        long windowMs = config.getAntiBotWindowSeconds() * 1000L;
        int maxConnections = config.getAntiBotMaxConnectionsPerIp();

        connectionHistory.computeIfAbsent(ip, k -> new ArrayList<>());
        List<Long> timestamps = connectionHistory.get(ip);

        synchronized (timestamps) {
            timestamps.removeIf(t -> t < now - windowMs);
            timestamps.add(now);

            if (timestamps.size() > maxConnections) {
                return Math.min(1.0,
                        (double) timestamps.size() / maxConnections);
            }
        }
        return 0.0;
    }

    private double checkGlobalRate() {
        long currentSecond = System.currentTimeMillis() / 1000;
        long lastSecond = lastSecondTimestamp.get();

        if (currentSecond != lastSecond) {
            lastSecondTimestamp.set(currentSecond);
            globalConnectionsThisSecond.set(1);
            return 0.0;
        }

        int count = globalConnectionsThisSecond.incrementAndGet();
        int max = config.getAntiBotGlobalMaxPerSecond();

        if (count > max) {
            return Math.min(1.0, (double) count / max);
        }
        return 0.0;
    }

    private double analyzeNamePattern(String username) {
        if (username == null || username.isEmpty()) return 1.0;

        double score = 0.0;

        // Check against known bot patterns
        for (Pattern pattern : BOT_NAME_PATTERNS) {
            if (pattern.matcher(username).matches()) {
                score += 0.5;
                break;
            }
        }

        // Check for excessive digits
        long digitCount = username.chars()
                .filter(Character::isDigit).count();
        double digitRatio = (double) digitCount / username.length();
        if (digitRatio > 0.6) {
            score += 0.3;
        }

        // Check for no vowels (random strings)
        String lower = username.toLowerCase();
        long vowelCount = lower.chars()
                .filter(c -> "aeiou".indexOf(c) >= 0).count();
        if (vowelCount == 0 && username.length() > 5) {
            score += 0.2;
        }

        // Check entropy — very low or very high both suspicious
        double entropy = calculateEntropy(username);
        if (entropy > 4.5 && username.length() >= 12) {
            score += 0.15; // Random-looking
        }

        return Math.min(1.0, score);
    }

    private double calculateEntropy(String str) {
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : str.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }
        double entropy = 0;
        for (int count : freq.values()) {
            double p = (double) count / str.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private void checkAttackMode() {
        long currentSecond = System.currentTimeMillis() / 1000;
        int count = globalConnectionsThisSecond.get();
        int threshold = config.getAntiBotGlobalMaxPerSecond() / 2;

        if (count > threshold && !attackMode) {
            attackMode = true;
            attackModeActivatedAt = System.currentTimeMillis();
            logger.warning("[AuthCraft AntiBot] ATTACK MODE ACTIVATED! "
                    + "High connection rate detected: "
                    + count + "/sec");
        }

        // Deactivate after 5 minutes of calm
        if (attackMode
                && System.currentTimeMillis() - attackModeActivatedAt
                > 300_000
                && count < threshold / 4) {
            attackMode = false;
            logger.info("[AuthCraft AntiBot] Attack mode deactivated");
        }
    }

    private void scheduleUnblock(String ip, long delayMs) {
        new Timer("AuthCraft-AntiBot-Unblock", true)
                .schedule(new TimerTask() {
                    @Override
                    public void run() {
                        blockedIps.remove(ip);
                    }
                }, delayMs);
    }

    /**
     * Manual block of an IP address.
     */
    public void blockIp(String ip) {
        blockedIps.add(ip);
    }

    /**
     * Manual unblock.
     */
    public void unblockIp(String ip) {
        blockedIps.remove(ip);
    }

    public boolean isAttackMode() {
        return attackMode;
    }

    public Set<String> getBlockedIps() {
        return Collections.unmodifiableSet(blockedIps);
    }

    /**
     * Cleanup old connection history entries.
     */
    public void cleanup() {
        long now = System.currentTimeMillis();
        long windowMs = config.getAntiBotWindowSeconds() * 1000L * 2;
        connectionHistory.entrySet().removeIf(entry -> {
            List<Long> timestamps = entry.getValue();
            synchronized (timestamps) {
                timestamps.removeIf(t -> t < now - windowMs);
                return timestamps.isEmpty();
            }
        });
    }

    // =============================================
    // Result class
    // =============================================

    public static class BotCheckResult {
        private final boolean allowed;
        private final double confidence;
        private final List<String> reasons;

        private BotCheckResult(boolean allowed, double confidence,
                               List<String> reasons) {
            this.allowed = allowed;
            this.confidence = confidence;
            this.reasons = reasons;
        }

        public static BotCheckResult allow() {
            return new BotCheckResult(true, 0, List.of());
        }

        public static BotCheckResult detected(double confidence,
                                              List<String> reasons) {
            return new BotCheckResult(false, confidence, reasons);
        }

        public static BotCheckResult blocked(String reason) {
            return new BotCheckResult(false, 1.0, List.of(reason));
        }

        public boolean isAllowed() { return allowed; }
        public double getConfidence() { return confidence; }
        public List<String> getReasons() { return reasons; }
    }
}