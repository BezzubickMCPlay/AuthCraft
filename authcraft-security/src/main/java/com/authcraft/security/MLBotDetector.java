// com/authcraft/security/MLBotDetector.java
package com.authcraft.security;

import com.authcraft.core.config.AuthCraftConfig;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Machine Learning-based Bot Detection System.
 * 
 * Features:
 * - Behavioral analysis of player connections
 * - Anomaly detection in login patterns
 * - ML-based username analysis
 * - Adaptive rate limiting based on threat level
 * - Integration with threat intelligence feeds
 */
public class MLBotDetector {

    private final AuthCraftConfig config;
    private final Logger logger;
    
    // Behavioral tracking
    private final Map<String, PlayerBehavior> playerBehaviors;
    private final Map<String, IPProfile> ipProfiles;
    
    // Global statistics for anomaly detection
    private final GlobalStats globalStats;
    
    // Threat intelligence
    private final ThreatIntelligenceFeed threatIntel;
    
    // Adaptive rate limiting
    private final AdaptiveRateLimiter rateLimiter;
    
    // ML model weights (simplified logistic regression)
    private final MLModel model;

    public MLBotDetector(AuthCraftConfig config, Logger logger) {
        this.config = config;
        this.logger = logger;
        this.playerBehaviors = new ConcurrentHashMap<>();
        this.ipProfiles = new ConcurrentHashMap<>();
        this.globalStats = new GlobalStats();
        this.threatIntel = new ThreatIntelligenceFeed();
        this.rateLimiter = new AdaptiveRateLimiter();
        this.model = new MLModel();
    }

    /**
     * Analyze a connection attempt and return a threat assessment.
     */
    public ThreatAssessment assessConnection(String ip, String username, String userAgent) {
        if (!config.isAntiBotEnabled()) {
            return ThreatAssessment.safe();
        }

        List<ThreatIndicator> indicators = new ArrayList<>();
        double threatScore = 0.0;

        // 1. Behavioral analysis
        double behaviorScore = analyzeBehavior(ip, username);
        if (behaviorScore > 0.3) {
            indicators.add(new ThreatIndicator(
                ThreatType.BEHAVIORAL_ANOMALY,
                behaviorScore,
                "Suspicious behavioral pattern detected"
            ));
        }
        threatScore += behaviorScore * 0.25;

        // 2. Anomaly detection
        double anomalyScore = detectAnomalies(ip, username);
        if (anomalyScore > 0.3) {
            indicators.add(new ThreatIndicator(
                ThreatType.LOGIN_ANOMALY,
                anomalyScore,
                "Login pattern anomaly detected"
            ));
        }
        threatScore += anomalyScore * 0.20;

        // 3. ML-based username analysis
        double usernameScore = analyzeUsernameML(username);
        if (usernameScore > 0.4) {
            indicators.add(new ThreatIndicator(
                ThreatType.SUSPICIOUS_USERNAME,
                usernameScore,
                "Username exhibits bot-like characteristics"
            ));
        }
        threatScore += usernameScore * 0.20;

        // 4. Threat intelligence check
        double intelScore = checkThreatIntelligence(ip);
        if (intelScore > 0) {
            indicators.add(new ThreatIndicator(
                ThreatType.KNOWN_THREAT,
                intelScore,
                "IP found in threat intelligence database"
            ));
        }
        threatScore += intelScore * 0.25;

        // 5. Adaptive rate limiting
        double rateLimitScore = rateLimiter.checkAndScore(ip);
        if (rateLimitScore > 0.5) {
            indicators.add(new ThreatIndicator(
                ThreatType.RATE_LIMIT_EXCEEDED,
                rateLimitScore,
                "Connection rate exceeds adaptive threshold"
            ));
        }
        threatScore += rateLimitScore * 0.10;

        // Normalize threat score
        threatScore = Math.min(1.0, threatScore);

        // Update profiles
        updateProfiles(ip, username, threatScore);

        return new ThreatAssessment(threatScore, indicators);
    }

    /**
     * Record a successful login for behavioral learning.
     */
    public void recordSuccessfulLogin(String ip, String username, long responseTime) {
        PlayerBehavior behavior = playerBehaviors.computeIfAbsent(
            username, k -> new PlayerBehavior()
        );
        behavior.recordLogin(ip, responseTime, true);
        
        IPProfile ipProfile = ipProfiles.computeIfAbsent(
            ip, k -> new IPProfile()
        );
        ipProfile.recordLogin(username, true);
        
        globalStats.recordSuccessfulLogin();
    }

    /**
     * Record a failed login attempt.
     */
    public void recordFailedLogin(String ip, String username) {
        PlayerBehavior behavior = playerBehaviors.computeIfAbsent(
            username, k -> new PlayerBehavior()
        );
        behavior.recordLogin(ip, 0, false);
        
        IPProfile ipProfile = ipProfiles.computeIfAbsent(
            ip, k -> new IPProfile()
        );
        ipProfile.recordLogin(username, false);
        
        globalStats.recordFailedLogin();
    }

    /**
     * Record player disconnect.
     */
    public void recordDisconnect(String username, long sessionDuration) {
        PlayerBehavior behavior = playerBehaviors.get(username);
        if (behavior != null) {
            behavior.recordDisconnect(sessionDuration);
        }
    }

    // === Behavioral Analysis ===

    private double analyzeBehavior(String ip, String username) {
        double score = 0.0;

        // Check IP profile
        IPProfile ipProfile = ipProfiles.get(ip);
        if (ipProfile != null) {
            // High failure rate from this IP
            if (ipProfile.getFailureRate() > 0.7) {
                score += 0.4;
            } else if (ipProfile.getFailureRate() > 0.5) {
                score += 0.2;
            }

            // Multiple accounts from same IP
            if (ipProfile.getUniqueAccounts() > 5) {
                score += 0.3;
            } else if (ipProfile.getUniqueAccounts() > 3) {
                score += 0.15;
            }

            // Rapid account switching
            if (ipProfile.getAccountSwitchRate() > 0.5) {
                score += 0.2;
            }
        }

        // Check player behavior
        PlayerBehavior behavior = playerBehaviors.get(username);
        if (behavior != null) {
            // Unusual login times
            if (behavior.hasUnusualLoginTimes()) {
                score += 0.15;
            }

            // Multiple IPs in short time
            if (behavior.getIpCount() > 3) {
                score += 0.25;
            }

            // Very short sessions (bot behavior)
            if (behavior.getAverageSessionDuration() < 5000 && behavior.getLoginCount() > 3) {
                score += 0.2;
            }
        }

        return Math.min(1.0, score);
    }

    // === Anomaly Detection ===

    private double detectAnomalies(String ip, String username) {
        double score = 0.0;

        // Compare current connection rate to baseline
        double currentRate = globalStats.getCurrentConnectionRate();
        double baselineRate = globalStats.getBaselineConnectionRate();
        
        if (baselineRate > 0) {
            double deviation = Math.abs(currentRate - baselineRate) / baselineRate;
            if (deviation > 3.0) {
                score += 0.5; // Significant deviation
            } else if (deviation > 2.0) {
                score += 0.3;
            } else if (deviation > 1.5) {
                score += 0.15;
            }
        }

        // Time-based anomaly detection
        int hour = java.time.LocalDateTime.now().getHour();
        double expectedRate = globalStats.getExpectedRateForHour(hour);
        double actualRate = globalStats.getCurrentRateForHour(hour);
        
        if (expectedRate > 0 && actualRate > expectedRate * 2) {
            score += 0.3;
        }

        // Geographic anomaly (if IP profile exists)
        IPProfile ipProfile = ipProfiles.get(ip);
        if (ipProfile != null && ipProfile.isNewLocation()) {
            score += 0.2;
        }

        return Math.min(1.0, score);
    }

    // === ML-based Username Analysis ===

    private double analyzeUsernameML(String username) {
        if (username == null || username.isEmpty()) {
            return 0.5;
        }

        double[] features = extractUsernameFeatures(username);
        return model.predict(features);
    }

    private double[] extractUsernameFeatures(String username) {
        double[] features = new double[12];
        
        // Feature 0: Length
        features[0] = Math.min(1.0, username.length() / 16.0);
        
        // Feature 1: Digit ratio
        long digits = username.chars().filter(Character::isDigit).count();
        features[1] = (double) digits / username.length();
        
        // Feature 2: Uppercase ratio
        long upper = username.chars().filter(Character::isUpperCase).count();
        features[2] = (double) upper / username.length();
        
        // Feature 3: Special chars ratio
        long special = username.chars().filter(c -> !Character.isLetterOrDigit(c)).count();
        features[3] = (double) special / username.length();
        
        // Feature 4: Entropy
        features[4] = calculateEntropy(username);
        
        // Feature 5: Consecutive digits
        features[5] = hasConsecutiveDigits(username) ? 1.0 : 0.0;
        
        // Feature 6: Consecutive letters
        features[6] = hasConsecutiveLetters(username) ? 1.0 : 0.0;
        
        // Feature 7: Repeated characters
        features[7] = hasRepeatedChars(username) ? 1.0 : 0.0;
        
        // Feature 8: Common bot patterns
        features[8] = matchesBotPattern(username) ? 1.0 : 0.0;
        
        // Feature 9: Dictionary word
        features[9] = isDictionaryWord(username) ? 0.0 : 1.0;
        
        // Feature 10: Leet speak
        features[10] = hasLeetSpeak(username) ? 1.0 : 0.0;
        
        // Feature 11: Random appearance score
        features[11] = calculateRandomnessScore(username);
        
        return features;
    }

    private double calculateEntropy(String str) {
        if (str.isEmpty()) return 0;
        
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : str.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }
        
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = (double) count / str.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        
        return Math.min(1.0, entropy / 5.0); // Normalize
    }

    private boolean hasConsecutiveDigits(String str) {
        return str.matches(".*\\d{4,}.*");
    }

    private boolean hasConsecutiveLetters(String str) {
        return str.matches(".*[a-zA-Z]{10,}.*");
    }

    private boolean hasRepeatedChars(String str) {
        return str.matches(".*(.)\\1{2,}.*");
    }

    private boolean matchesBotPattern(String str) {
        String lower = str.toLowerCase();
        return lower.matches("bot\\d*") ||
               lower.matches("player_?\\d+") ||
               lower.matches("\\d{8,}") ||
               lower.matches("user\\d*") ||
               lower.matches("test\\d*") ||
               lower.matches("hack(er)?\\d*");
    }

    private boolean isDictionaryWord(String str) {
        // Common English words (simplified)
        Set<String> commonWords = Set.of(
            "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
            "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
            "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
            "or", "an", "will", "my", "one", "all", "would", "there", "their", "what"
        );
        return commonWords.contains(str.toLowerCase());
    }

    private boolean hasLeetSpeak(String str) {
        return str.contains("1") && (str.contains("e") || str.contains("E")) ||
               str.contains("0") && (str.contains("o") || str.contains("O")) ||
               str.contains("3") && (str.contains("e") || str.contains("E")) ||
               str.contains("7") && (str.contains("t") || str.contains("T"));
    }

    private double calculateRandomnessScore(String str) {
        // Check for random character distribution
        int transitions = 0;
        for (int i = 1; i < str.length(); i++) {
            char prev = str.charAt(i - 1);
            char curr = str.charAt(i);
            
            // Count character type transitions
            boolean prevUpper = Character.isUpperCase(prev);
            boolean prevDigit = Character.isDigit(prev);
            boolean currUpper = Character.isUpperCase(curr);
            boolean currDigit = Character.isDigit(curr);
            
            if (prevUpper != currUpper || prevDigit != currDigit) {
                transitions++;
            }
        }
        
        // High transition count suggests randomness
        return Math.min(1.0, (double) transitions / str.length());
    }

    // === Threat Intelligence ===

    private double checkThreatIntelligence(String ip) {
        return threatIntel.checkIP(ip);
    }

    // === Profile Updates ===

    private void updateProfiles(String ip, String username, double threatScore) {
        IPProfile ipProfile = ipProfiles.computeIfAbsent(
            ip, k -> new IPProfile()
        );
        ipProfile.recordConnectionAttempt(username, threatScore);
    }

    /**
     * Cleanup old data periodically.
     */
    public void cleanup() {
        long cutoff = System.currentTimeMillis() - 3600000; // 1 hour
        
        playerBehaviors.entrySet().removeIf(e -> 
            e.getValue().getLastActivity() < cutoff
        );
        
        ipProfiles.entrySet().removeIf(e -> 
            e.getValue().getLastActivity() < cutoff
        );
        
        globalStats.cleanup();
        rateLimiter.cleanup();
    }

    // === Inner Classes ===

    /**
     * Player behavior tracking for ML analysis.
     */
    private static class PlayerBehavior {
        private final List<Long> loginTimes = new ArrayList<>();
        private final Set<String> usedIPs = new HashSet<>();
        private final List<Long> sessionDurations = new ArrayList<>();
        private final List<Boolean> loginResults = new ArrayList<>();
        private long lastActivity = System.currentTimeMillis();

        public void recordLogin(String ip, long responseTime, boolean success) {
            loginTimes.add(System.currentTimeMillis());
            usedIPs.add(ip);
            loginResults.add(success);
            lastActivity = System.currentTimeMillis();
        }

        public void recordDisconnect(long sessionDuration) {
            sessionDurations.add(sessionDuration);
            lastActivity = System.currentTimeMillis();
        }

        public boolean hasUnusualLoginTimes() {
            if (loginTimes.size() < 5) return false;
            
            // Check if logins are at unusual hours
            int nightLogins = 0;
            for (long time : loginTimes) {
                java.time.LocalDateTime dt = java.time.LocalDateTime.ofEpochSecond(
                    time / 1000, 0, java.time.ZoneOffset.UTC
                );
                int hour = dt.getHour();
                if (hour >= 2 && hour <= 5) {
                    nightLogins++;
                }
            }
            return (double) nightLogins / loginTimes.size() > 0.7;
        }

        public int getIpCount() {
            return usedIPs.size();
        }

        public long getAverageSessionDuration() {
            if (sessionDurations.isEmpty()) return 0;
            return (long) sessionDurations.stream()
                .mapToLong(Long::longValue)
                .average()
                .orElse(0);
        }

        public int getLoginCount() {
            return loginTimes.size();
        }

        public long getLastActivity() {
            return lastActivity;
        }
    }

    /**
     * IP profile for tracking connection patterns.
     */
    private static class IPProfile {
        private final Set<String> accounts = new HashSet<>();
        private final List<Boolean> loginResults = new ArrayList<>();
        private final List<Long> connectionTimes = new ArrayList<>();
        private final List<Double> threatScores = new ArrayList<>();
        private long lastActivity = System.currentTimeMillis();
        private String lastAccount = "";
        private int accountSwitches = 0;
        private boolean newLocation = false;

        public void recordLogin(String username, boolean success) {
            accounts.add(username);
            loginResults.add(success);
            lastActivity = System.currentTimeMillis();
            
            if (!lastAccount.isEmpty() && !lastAccount.equals(username)) {
                accountSwitches++;
            }
            lastAccount = username;
        }

        public void recordConnectionAttempt(String username, double threatScore) {
            connectionTimes.add(System.currentTimeMillis());
            threatScores.add(threatScore);
            lastActivity = System.currentTimeMillis();
        }

        public double getFailureRate() {
            if (loginResults.isEmpty()) return 0;
            long failures = loginResults.stream().filter(b -> !b).count();
            return (double) failures / loginResults.size();
        }

        public int getUniqueAccounts() {
            return accounts.size();
        }

        public double getAccountSwitchRate() {
            if (loginResults.size() < 2) return 0;
            return (double) accountSwitches / loginResults.size();
        }

        public boolean isNewLocation() {
            return newLocation;
        }

        public long getLastActivity() {
            return lastActivity;
        }
    }

    /**
     * Global statistics for anomaly detection.
     */
    private static class GlobalStats {
        private final Map<Integer, List<Long>> hourlyConnections = new HashMap<>();
        private final List<Long> connectionTimes = new ArrayList<>();
        private final AtomicInteger successfulLogins = new AtomicInteger(0);
        private final AtomicInteger failedLogins = new AtomicInteger(0);
        private long baselineEstablished = 0;
        private double baselineRate = 0;

        public void recordSuccessfulLogin() {
            successfulLogins.incrementAndGet();
            recordConnection();
        }

        public void recordFailedLogin() {
            failedLogins.incrementAndGet();
            recordConnection();
        }

        private void recordConnection() {
            long now = System.currentTimeMillis();
            connectionTimes.add(now);
            
            int hour = java.time.LocalDateTime.now().getHour();
            hourlyConnections.computeIfAbsent(hour, k -> new ArrayList<>()).add(now);
            
            // Establish baseline after 100 connections
            if (connectionTimes.size() == 100 && baselineRate == 0) {
                baselineRate = calculateCurrentRate();
                baselineEstablished = now;
            }
        }

        public double getCurrentConnectionRate() {
            return calculateCurrentRate();
        }

        private double calculateCurrentRate() {
            if (connectionTimes.size() < 2) return 0;
            
            long now = System.currentTimeMillis();
            long oneMinuteAgo = now - 60000;
            
            long recent = connectionTimes.stream()
                .filter(t -> t > oneMinuteAgo)
                .count();
            
            return recent / 60.0; // Per second
        }

        public double getBaselineConnectionRate() {
            return baselineRate;
        }

        public double getExpectedRateForHour(int hour) {
            List<Long> hourly = hourlyConnections.get(hour);
            if (hourly == null || hourly.isEmpty()) return 0;
            
            // Calculate average for this hour
            return hourly.size() / 60.0; // Simplified
        }

        public double getCurrentRateForHour(int hour) {
            List<Long> hourly = hourlyConnections.get(hour);
            if (hourly == null) return 0;
            
            long now = System.currentTimeMillis();
            long oneMinuteAgo = now - 60000;
            
            return hourly.stream()
                .filter(t -> t > oneMinuteAgo)
                .count() / 60.0;
        }

        public void cleanup() {
            long cutoff = System.currentTimeMillis() - 3600000; // 1 hour
            connectionTimes.removeIf(t -> t < cutoff);
            hourlyConnections.values().forEach(list -> 
                list.removeIf(t -> t < cutoff)
            );
        }
    }

    /**
     * Adaptive rate limiter that adjusts thresholds based on threat level.
     */
    private static class AdaptiveRateLimiter {
        private final Map<String, RateLimitEntry> ipLimits = new ConcurrentHashMap<>();
        private volatile double currentThreatLevel = 0.0;
        private volatile int baseLimit = 10; // Base requests per minute

        public double checkAndScore(String ip) {
            RateLimitEntry entry = ipLimits.computeIfAbsent(
                ip, k -> new RateLimitEntry()
            );
            
            int adaptiveLimit = calculateAdaptiveLimit();
            entry.recordRequest();
            
            int requests = entry.getRequestCount();
            if (requests > adaptiveLimit) {
                return Math.min(1.0, (double) requests / adaptiveLimit - 1.0);
            }
            
            return 0.0;
        }

        private int calculateAdaptiveLimit() {
            // Reduce limit when threat level is high
            double reduction = currentThreatLevel * 0.7;
            return (int) (baseLimit * (1.0 - reduction));
        }

        public void updateThreatLevel(double level) {
            this.currentThreatLevel = level;
        }

        public void cleanup() {
            long cutoff = System.currentTimeMillis() - 60000;
            ipLimits.entrySet().removeIf(e -> 
                e.getValue().getLastRequest() < cutoff
            );
        }
    }

    private static class RateLimitEntry {
        private final List<Long> requests = new ArrayList<>();
        
        public void recordRequest() {
            requests.add(System.currentTimeMillis());
            // Keep only last minute
            long cutoff = System.currentTimeMillis() - 60000;
            requests.removeIf(t -> t < cutoff);
        }
        
        public int getRequestCount() {
            return requests.size();
        }
        
        public long getLastRequest() {
            return requests.isEmpty() ? 0 : requests.get(requests.size() - 1);
        }
    }

    /**
     * Threat intelligence feed integration.
     */
    private static class ThreatIntelligenceFeed {
        // Known malicious IP ranges (simplified)
        private static final Set<String> KNOWN_BAD_IPS = new HashSet<>();
        private static final List<String> TOR_EXIT_NODES = new ArrayList<>();
        
        static {
            // Initialize with some known patterns
            // In production, this would be fetched from external feeds
        }

        public double checkIP(String ip) {
            if (KNOWN_BAD_IPS.contains(ip)) {
                return 1.0;
            }
            
            // Check for Tor exit nodes
            for (String torRange : TOR_EXIT_NODES) {
                if (ip.startsWith(torRange)) {
                    return 0.8;
                }
            }
            
            return 0.0;
        }

        public void addKnownBadIP(String ip) {
            KNOWN_BAD_IPS.add(ip);
        }

        public void addTorExitNode(String range) {
            TOR_EXIT_NODES.add(range);
        }
    }

    /**
     * Simplified ML model for username classification.
     * Uses logistic regression with pre-trained weights.
     */
    private static class MLModel {
        // Pre-trained weights (would be loaded from model file in production)
        private static final double[] WEIGHTS = {
            0.05,   // Length
            0.25,   // Digit ratio
            0.10,   // Uppercase ratio
            0.15,   // Special chars ratio
            0.20,   // Entropy
            0.15,   // Consecutive digits
            0.05,   // Consecutive letters
            0.10,   // Repeated chars
            0.30,   // Bot pattern match
            -0.10,  // Dictionary word
            0.15,   // Leet speak
            0.20    // Randomness
        };
        
        private static final double BIAS = -0.5;

        public double predict(double[] features) {
            double sum = BIAS;
            for (int i = 0; i < features.length && i < WEIGHTS.length; i++) {
                sum += features[i] * WEIGHTS[i];
            }
            // Sigmoid activation
            return 1.0 / (1.0 + Math.exp(-sum));
        }
    }

    // === Result Classes ===

    /**
     * Threat assessment result.
     */
    public static class ThreatAssessment {
        private final double threatScore;
        private final List<ThreatIndicator> indicators;
        private final boolean isBot;

        public ThreatAssessment(double threatScore, List<ThreatIndicator> indicators) {
            this.threatScore = threatScore;
            this.indicators = indicators;
            this.isBot = threatScore > 0.5;
        }

        public static ThreatAssessment safe() {
            return new ThreatAssessment(0.0, Collections.emptyList());
        }

        public double getThreatScore() {
            return threatScore;
        }

        public List<ThreatIndicator> getIndicators() {
            return indicators;
        }

        public boolean isBot() {
            return isBot;
        }

        public boolean shouldBlock() {
            return threatScore > 0.7;
        }

        public boolean shouldChallenge() {
            return threatScore > 0.4 && threatScore <= 0.7;
        }
    }

    /**
     * Individual threat indicator.
     */
    public static class ThreatIndicator {
        private final ThreatType type;
        private final double confidence;
        private final String description;

        public ThreatIndicator(ThreatType type, double confidence, String description) {
            this.type = type;
            this.confidence = confidence;
            this.description = description;
        }

        public ThreatType getType() {
            return type;
        }

        public double getConfidence() {
            return confidence;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Types of threats that can be detected.
     */
    public enum ThreatType {
        BEHAVIORAL_ANOMALY,
        LOGIN_ANOMALY,
        SUSPICIOUS_USERNAME,
        KNOWN_THREAT,
        RATE_LIMIT_EXCEEDED,
        VPN_DETECTED,
        TOR_EXIT_NODE,
        PROXY_DETECTED,
        GEOLOCATION_MISMATCH
    }
}
