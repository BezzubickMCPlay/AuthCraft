// com/authcraft/security/ThreatProtectionService.java
package com.authcraft.security;

import com.authcraft.core.config.AuthCraftConfig;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Advanced Threat Protection Service.
 * 
 * Features:
 * - VPN/Proxy detection
 * - Tor exit node blocking
 * - Known malicious IP database
 * - Automatic IP reputation scoring
 * - Distributed attack detection
 */
public class ThreatProtectionService {

    private final AuthCraftConfig config;
    private final Logger logger;
    
    // IP reputation cache
    private final Map<String, IPReputation> reputationCache;
    
    // Tor exit nodes
    private final Set<String> torExitNodes;
    private long torNodesLastUpdated;
    
    // VPN/Proxy ranges
    private final Set<String> vpnProxyRanges;
    private long vpnRangesLastUpdated;
    
    // Known malicious IPs
    private final Set<String> maliciousIPs;
    
    // IP reputation statistics
    private final Map<String, IPStats> ipStats;
    
    // Distributed attack detection
    private final DistributedAttackDetector attackDetector;
    
    // External API endpoints
    private static final String TOR_EXIT_NODES_URL = "https://check.torproject.org/exit-addresses";
    private static final String IP_API_URL = "http://ip-api.com/json/";
    
    // Update intervals
    private static final long TOR_UPDATE_INTERVAL = 3600000; // 1 hour
    private static final long VPN_UPDATE_INTERVAL = 86400000; // 24 hours
    private static final long REPUTATION_CACHE_TTL = 1800000; // 30 minutes

    public ThreatProtectionService(AuthCraftConfig config, Logger logger) {
        this.config = config;
        this.logger = logger;
        this.reputationCache = new ConcurrentHashMap<>();
        this.torExitNodes = ConcurrentHashMap.newKeySet();
        this.vpnProxyRanges = ConcurrentHashMap.newKeySet();
        this.maliciousIPs = ConcurrentHashMap.newKeySet();
        this.ipStats = new ConcurrentHashMap<>();
        this.attackDetector = new DistributedAttackDetector();
        
        // Initialize with built-in data
        initializeBuiltInData();
    }

    /**
     * Check an IP address for threats.
     */
    public ThreatCheckResult checkIP(String ip) {
        List<ThreatType> threats = new ArrayList<>();
        double threatScore = 0.0;
        
        // 1. Check if IP is a Tor exit node
        if (isTorExitNode(ip)) {
            threats.add(ThreatType.TOR_EXIT_NODE);
            threatScore += 0.8;
        }
        
        // 2. Check if IP is a VPN/Proxy
        if (isVPNOrProxy(ip)) {
            threats.add(ThreatType.VPN_PROXY);
            threatScore += 0.5;
        }
        
        // 3. Check if IP is in malicious IP database
        if (isMaliciousIP(ip)) {
            threats.add(ThreatType.MALICIOUS_IP);
            threatScore += 1.0;
        }
        
        // 4. Get IP reputation score
        IPReputation reputation = getIPReputation(ip);
        if (reputation.getScore() > 0.5) {
            threats.add(ThreatType.BAD_REPUTATION);
            threatScore += reputation.getScore() * 0.5;
        }
        
        // 5. Check for distributed attack patterns
        if (attackDetector.isPartOfAttack(ip)) {
            threats.add(ThreatType.DISTRIBUTED_ATTACK);
            threatScore += 0.6;
        }
        
        // Normalize score
        threatScore = Math.min(1.0, threatScore);
        
        return new ThreatCheckResult(threatScore, threats, reputation);
    }

    /**
     * Record a login attempt for reputation tracking.
     */
    public void recordLoginAttempt(String ip, boolean successful, String username) {
        IPStats stats = ipStats.computeIfAbsent(ip, k -> new IPStats());
        stats.recordAttempt(successful, username);
        
        // Update reputation based on activity
        updateReputationFromStats(ip, stats);
        
        // Track for distributed attack detection
        attackDetector.recordAttempt(ip, successful, username);
    }

    /**
     * Check if IP is a Tor exit node.
     */
    public boolean isTorExitNode(String ip) {
        updateTorNodesIfNeeded();
        return torExitNodes.contains(ip);
    }

    /**
     * Check if IP is a VPN or Proxy.
     */
    public boolean isVPNOrProxy(String ip) {
        updateVPNRangesIfNeeded();
        
        // Check exact match
        if (vpnProxyRanges.contains(ip)) {
            return true;
        }
        
        // Check CIDR ranges
        for (String range : vpnProxyRanges) {
            if (range.contains("/") && isInCIDRRange(ip, range)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if IP is in malicious IP database.
     */
    public boolean isMaliciousIP(String ip) {
        return maliciousIPs.contains(ip);
    }

    /**
     * Get IP reputation score.
     */
    public IPReputation getIPReputation(String ip) {
        // Check cache first
        IPReputation cached = reputationCache.get(ip);
        if (cached != null && !cached.isExpired()) {
            return cached;
        }
        
        // Calculate reputation
        IPReputation reputation = calculateReputation(ip);
        reputationCache.put(ip, reputation);
        
        return reputation;
    }

    /**
     * Add an IP to the malicious IP list.
     */
    public void addMaliciousIP(String ip) {
        maliciousIPs.add(ip);
        logger.warning("[ThreatProtection] Added malicious IP: " + ip);
    }

    /**
     * Remove an IP from the malicious IP list.
     */
    public void removeMaliciousIP(String ip) {
        maliciousIPs.remove(ip);
    }

    /**
     * Add a VPN/Proxy range.
     */
    public void addVPNProxyRange(String range) {
        vpnProxyRanges.add(range);
    }

    // === Private Methods ===

    private void initializeBuiltInData() {
        // Known Tor exit nodes (sample - should be updated from API)
        // These are example IPs and should be replaced with actual data
        
        // Known VPN/Proxy ranges (sample)
        vpnProxyRanges.add("10.0.0.0/8");      // Private
        vpnProxyRanges.add("172.16.0.0/12");   // Private
        vpnProxyRanges.add("192.168.0.0/16");  // Private
        vpnProxyRanges.add("100.64.0.0/10");   // CGNAT
        
        // Known malicious IPs (sample - should be loaded from threat intel)
    }

    private void updateTorNodesIfNeeded() {
        long now = System.currentTimeMillis();
        if (now - torNodesLastUpdated > TOR_UPDATE_INTERVAL) {
            updateTorNodes();
            torNodesLastUpdated = now;
        }
    }

    private void updateTorNodes() {
        try {
            // In production, fetch from Tor Project API
            // For now, we'll use a simplified approach
            logger.info("[ThreatProtection] Updating Tor exit nodes list...");
            
            // Parse Tor exit node list
            // This would normally fetch from TOR_EXIT_NODES_URL
            // For now, we'll keep the existing set
        } catch (Exception e) {
            logger.warning("[ThreatProtection] Failed to update Tor nodes: " + e.getMessage());
        }
    }

    private void updateVPNRangesIfNeeded() {
        long now = System.currentTimeMillis();
        if (now - vpnRangesLastUpdated > VPN_UPDATE_INTERVAL) {
            updateVPNRanges();
            vpnRangesLastUpdated = now;
        }
    }

    private void updateVPNRanges() {
        try {
            logger.info("[ThreatProtection] Updating VPN/Proxy ranges...");
            // In production, fetch from threat intelligence API
        } catch (Exception e) {
            logger.warning("[ThreatProtection] Failed to update VPN ranges: " + e.getMessage());
        }
    }

    private IPReputation calculateReputation(String ip) {
        IPStats stats = ipStats.get(ip);
        
        double score = 0.0;
        int totalAttempts = 0;
        int failedAttempts = 0;
        int uniqueAccounts = 0;
        long firstSeen = System.currentTimeMillis();
        long lastSeen = System.currentTimeMillis();
        
        if (stats != null) {
            totalAttempts = stats.getTotalAttempts();
            failedAttempts = stats.getFailedAttempts();
            uniqueAccounts = stats.getUniqueAccounts();
            firstSeen = stats.getFirstSeen();
            lastSeen = stats.getLastSeen();
            
            // Calculate reputation based on behavior
            if (totalAttempts > 0) {
                double failureRate = (double) failedAttempts / totalAttempts;
                
                // High failure rate = bad reputation
                if (failureRate > 0.8) {
                    score += 0.5;
                } else if (failureRate > 0.5) {
                    score += 0.3;
                } else if (failureRate > 0.3) {
                    score += 0.1;
                }
                
                // Multiple accounts from same IP
                if (uniqueAccounts > 10) {
                    score += 0.3;
                } else if (uniqueAccounts > 5) {
                    score += 0.15;
                } else if (uniqueAccounts > 3) {
                    score += 0.05;
                }
                
                // Rapid attempts (bot behavior)
                long timeSpan = lastSeen - firstSeen;
                if (timeSpan > 0 && totalAttempts > 5) {
                    double attemptsPerMinute = (double) totalAttempts / (timeSpan / 60000.0);
                    if (attemptsPerMinute > 10) {
                        score += 0.2;
                    } else if (attemptsPerMinute > 5) {
                        score += 0.1;
                    }
                }
            }
        }
        
        // Check external reputation services (if enabled)
        // This would call external APIs in production
        
        return new IPReputation(
            Math.min(1.0, score),
            totalAttempts,
            failedAttempts,
            uniqueAccounts,
            firstSeen,
            lastSeen
        );
    }

    private void updateReputationFromStats(String ip, IPStats stats) {
        IPReputation reputation = calculateReputation(ip);
        reputationCache.put(ip, reputation);
    }

    private boolean isInCIDRRange(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/");
            String network = parts[0];
            int prefix = Integer.parseInt(parts[1]);
            
            long ipLong = ipToLong(ip);
            long networkLong = ipToLong(network);
            long mask = -1L << (32 - prefix);
            
            return (ipLong & mask) == (networkLong & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = result << 8;
            result += Integer.parseInt(parts[i]);
        }
        return result;
    }

    /**
     * Cleanup old data periodically.
     */
    public void cleanup() {
        long cutoff = System.currentTimeMillis() - REPUTATION_CACHE_TTL;
        
        reputationCache.entrySet().removeIf(e -> 
            e.getValue().getLastSeen() < cutoff
        );
        
        ipStats.entrySet().removeIf(e -> 
            e.getValue().getLastSeen() < cutoff
        );
        
        attackDetector.cleanup();
    }

    // === Inner Classes ===

    /**
     * IP Reputation information.
     */
    public static class IPReputation {
        private final double score;
        private final int totalAttempts;
        private final int failedAttempts;
        private final int uniqueAccounts;
        private final long firstSeen;
        private final long lastSeen;
        private final long calculatedAt;

        public IPReputation(double score, int totalAttempts, int failedAttempts,
                           int uniqueAccounts, long firstSeen, long lastSeen) {
            this.score = score;
            this.totalAttempts = totalAttempts;
            this.failedAttempts = failedAttempts;
            this.uniqueAccounts = uniqueAccounts;
            this.firstSeen = firstSeen;
            this.lastSeen = lastSeen;
            this.calculatedAt = System.currentTimeMillis();
        }

        public double getScore() { return score; }
        public int getTotalAttempts() { return totalAttempts; }
        public int getFailedAttempts() { return failedAttempts; }
        public int getUniqueAccounts() { return uniqueAccounts; }
        public long getFirstSeen() { return firstSeen; }
        public long getLastSeen() { return lastSeen; }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - calculatedAt > REPUTATION_CACHE_TTL;
        }
        
        public String getRiskLevel() {
            if (score >= 0.7) return "HIGH";
            if (score >= 0.4) return "MEDIUM";
            if (score >= 0.2) return "LOW";
            return "MINIMAL";
        }
    }

    /**
     * IP statistics tracking.
     */
    private static class IPStats {
        private final AtomicInteger totalAttempts = new AtomicInteger(0);
        private final AtomicInteger failedAttempts = new AtomicInteger(0);
        private final Set<String> accounts = ConcurrentHashMap.newKeySet();
        private final AtomicLong firstSeen = new AtomicLong(System.currentTimeMillis());
        private final AtomicLong lastSeen = new AtomicLong(System.currentTimeMillis());

        public void recordAttempt(boolean successful, String username) {
            totalAttempts.incrementAndGet();
            if (!successful) {
                failedAttempts.incrementAndGet();
            }
            if (username != null) {
                accounts.add(username);
            }
            lastSeen.set(System.currentTimeMillis());
        }

        public int getTotalAttempts() { return totalAttempts.get(); }
        public int getFailedAttempts() { return failedAttempts.get(); }
        public int getUniqueAccounts() { return accounts.size(); }
        public long getFirstSeen() { return firstSeen.get(); }
        public long getLastSeen() { return lastSeen.get(); }
    }

    /**
     * Distributed attack detection.
     */
    private static class DistributedAttackDetector {
        private final Map<String, AttackPattern> patterns = new ConcurrentHashMap<>();
        private final Map<String, Integer> globalUsernameAttempts = new ConcurrentHashMap<>();
        private final AtomicLong lastCleanup = new AtomicLong(System.currentTimeMillis());

        public void recordAttempt(String ip, boolean successful, String username) {
            // Track username attempts globally
            if (username != null) {
                globalUsernameAttempts.merge(username, 1, Integer::sum);
            }
            
            // Track IP patterns
            AttackPattern pattern = patterns.computeIfAbsent(
                ip, k -> new AttackPattern()
            );
            pattern.recordAttempt(username, successful);
        }

        public boolean isPartOfAttack(String ip) {
            AttackPattern pattern = patterns.get(ip);
            if (pattern == null) return false;
            
            // Check if this IP is part of a coordinated attack
            String targetUsername = pattern.getPrimaryTarget();
            if (targetUsername != null) {
                int globalAttempts = globalUsernameAttempts.getOrDefault(targetUsername, 0);
                // If many IPs are attacking the same username
                return globalAttempts > 20;
            }
            
            return false;
        }

        public void cleanup() {
            long now = System.currentTimeMillis();
            if (now - lastCleanup.get() > 300000) { // 5 minutes
                long cutoff = now - 3600000; // 1 hour
                patterns.entrySet().removeIf(e -> 
                    e.getValue().getLastAttempt() < cutoff
                );
                globalUsernameAttempts.clear();
                lastCleanup.set(now);
            }
        }
    }

    private static class AttackPattern {
        private final Map<String, AtomicInteger> usernameAttempts = new ConcurrentHashMap<>();
        private final AtomicInteger totalAttempts = new AtomicInteger(0);
        private final AtomicLong lastAttempt = new AtomicLong(System.currentTimeMillis());

        public void recordAttempt(String username, boolean successful) {
            totalAttempts.incrementAndGet();
            if (username != null) {
                usernameAttempts.computeIfAbsent(username, k -> new AtomicInteger(0))
                    .incrementAndGet();
            }
            lastAttempt.set(System.currentTimeMillis());
        }

        public String getPrimaryTarget() {
            return usernameAttempts.entrySet().stream()
                .max(Comparator.comparingInt(e -> e.getValue().get()))
                .map(Map.Entry::getKey)
                .orElse(null);
        }

        public long getLastAttempt() {
            return lastAttempt.get();
        }
    }

    /**
     * Threat check result.
     */
    public static class ThreatCheckResult {
        private final double threatScore;
        private final List<ThreatType> threats;
        private final IPReputation reputation;

        public ThreatCheckResult(double threatScore, List<ThreatType> threats, 
                                IPReputation reputation) {
            this.threatScore = threatScore;
            this.threats = threats;
            this.reputation = reputation;
        }

        public double getThreatScore() { return threatScore; }
        public List<ThreatType> getThreats() { return threats; }
        public IPReputation getReputation() { return reputation; }
        
        public boolean hasThreats() {
            return !threats.isEmpty();
        }
        
        public boolean shouldBlock() {
            return threatScore >= 0.7;
        }
        
        public boolean shouldChallenge() {
            return threatScore >= 0.4 && threatScore < 0.7;
        }
        
        public boolean isSafe() {
            return threatScore < 0.4;
        }
    }

    /**
     * Types of threats that can be detected.
     */
    public enum ThreatType {
        TOR_EXIT_NODE("Tor Exit Node"),
        VPN_PROXY("VPN/Proxy"),
        MALICIOUS_IP("Known Malicious IP"),
        BAD_REPUTATION("Bad IP Reputation"),
        DISTRIBUTED_ATTACK("Distributed Attack"),
        DATA_CENTER("Data Center IP"),
        HOSTING_PROVIDER("Hosting Provider"),
        BLACKLISTED("Blacklisted");

        private final String description;

        ThreatType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}
