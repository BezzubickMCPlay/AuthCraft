// com/authcraft/core/service/CommunityService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.TwoFactorMethod;

import java.util.logging.Logger;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Community features service for player profiles, achievements, and security leaderboards.
 */
public class CommunityService {

    private final AuthCraftConfig config;
    private final StorageProvider storage;
    private final PlatformAdapter platform;
    private final AuditService auditService;
    private final Logger logger;

    // Player profiles cache
    private final Map<UUID, PlayerProfile> profileCache = new ConcurrentHashMap<>();
    private long lastProfileUpdate = 0;

    // Achievements
    private final Map<String, Achievement> achievements = new ConcurrentHashMap<>();
    private final Map<UUID, Set<String>> playerAchievements = new ConcurrentHashMap<>();

    // Security scores
    private final Map<UUID, SecurityScore> securityScores = new ConcurrentHashMap<>();
    private final List<LeaderboardEntry> leaderboardCache = Collections.synchronizedList(new ArrayList<>());
    private long lastLeaderboardUpdate = 0;

    // Security challenges
    private final Map<String, SecurityChallenge> activeChallenges = new ConcurrentHashMap<>();
    private final Map<UUID, Set<String>> playerChallenges = new ConcurrentHashMap<>();
    private final Map<UUID, ChallengeProgress> challengeProgress = new ConcurrentHashMap<>();

    // Bug bounty
    private final Map<String, BugBountyReport> bugReports = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> playerBountyPoints = new ConcurrentHashMap<>();

    private static final long CACHE_TTL = 300000; // 5 minutes
    private static final int MAX_LEADERBOARD_SIZE = 100;

    public CommunityService(AuthCraftConfig config, StorageProvider storage,
                            PlatformAdapter platform, AuditService auditService) {
        this.config = config;
        this.storage = storage;
        this.platform = platform;
        this.auditService = auditService;
        this.logger = Logger.getLogger("AuthCraft-Community");

        initializeAchievements();
    }

    // === Initialization ===

    private void initializeAchievements() {
        // Security achievements
        achievements.put("first_2fa", new Achievement(
            "first_2fa", "Security Starter", "Enable two-factor authentication",
            AchievementType.SECURITY, AchievementRarity.COMMON, 10
        ));

        achievements.put("2fa_master", new Achievement(
            "2fa_master", "2FA Master", "Enable all available 2FA methods",
            AchievementType.SECURITY, AchievementRarity.RARE, 50
        ));

        achievements.put("password_strong", new Achievement(
            "password_strong", "Fort Knox", "Set a very strong password",
            AchievementType.SECURITY, AchievementRarity.UNCOMMON, 20
        ));

        achievements.put("trusted_device", new Achievement(
            "trusted_device", "Trusted User", "Add a trusted device",
            AchievementType.SECURITY, AchievementRarity.COMMON, 10
        ));

        achievements.put("security_week", new Achievement(
            "security_week", "Security Week", "Stay secure for 7 consecutive days",
            AchievementType.SECURITY, AchievementRarity.UNCOMMON, 30
        ));

        achievements.put("security_month", new Achievement(
            "security_month", "Security Month", "Stay secure for 30 consecutive days",
            AchievementType.SECURITY, AchievementRarity.RARE, 100
        ));

        achievements.put("no_failed_logins", new Achievement(
            "no_failed_logins", "Perfect Record", "No failed login attempts for 30 days",
            AchievementType.SECURITY, AchievementRarity.RARE, 75
        ));

        achievements.put("security_challenge_1", new Achievement(
            "security_challenge_1", "Challenge Accepted", "Complete a security challenge",
            AchievementType.CHALLENGE, AchievementRarity.UNCOMMON, 25
        ));

        achievements.put("security_challenge_5", new Achievement(
            "security_challenge_5", "Challenge Champion", "Complete 5 security challenges",
            AchievementType.CHALLENGE, AchievementRarity.RARE, 100
        ));

        achievements.put("bug_hunter", new Achievement(
            "bug_hunter", "Bug Hunter", "Submit a valid bug bounty report",
            AchievementType.CONTRIBUTION, AchievementRarity.EPIC, 150
        ));

        achievements.put("early_adopter", new Achievement(
            "early_adopter", "Early Adopter", "Joined in the first month",
            AchievementType.SPECIAL, AchievementRarity.LEGENDARY, 200
        ));

        achievements.put("security_advocate", new Achievement(
            "security_advocate", "Security Advocate", "Help 10 players improve their security",
            AchievementType.SOCIAL, AchievementRarity.EPIC, 150
        ));

        // Account age achievements
        achievements.put("account_1_year", new Achievement(
            "account_1_year", "One Year Strong", "Account is 1 year old",
            AchievementType.VETERAN, AchievementRarity.RARE, 100
        ));

        achievements.put("account_2_years", new Achievement(
            "account_2_years", "Two Year Veteran", "Account is 2 years old",
            AchievementType.VETERAN, AchievementRarity.EPIC, 200
        ));
    }

    // === Player Profiles ===

    /**
     * Get a player's profile.
     */
    public CompletableFuture<PlayerProfile> getPlayerProfile(UUID playerUuid) {
        // Check cache
        if (System.currentTimeMillis() - lastProfileUpdate < CACHE_TTL) {
            PlayerProfile cached = profileCache.get(playerUuid);
            if (cached != null) {
                return CompletableFuture.completedFuture(cached);
            }
        }

        return storage.getAccount(playerUuid).thenApply(optAccount -> {
            if (optAccount.isEmpty()) {
                return null;
            }

            Account account = optAccount.get();
            PlayerProfile profile = buildProfile(account);
            profileCache.put(playerUuid, profile);
            return profile;
        });
    }

    private PlayerProfile buildProfile(Account account) {
        PlayerProfile profile = new PlayerProfile(
            account.getUuid(),
            account.getUsername(),
            account.getCreatedAt(),
            account.getLastLoginDate()
        );

        // Security status
        profile.setHas2FA(account.getTwoFactorMethod() != TwoFactorMethod.NONE);
        profile.setTwoFactorMethods(account.getEnabledTwoFactorMethods());

        // Calculate security score
        SecurityScore score = calculateSecurityScore(account);
        profile.setSecurityScore(score);

        // Get achievements
        Set<String> playerAchs = playerAchievements.getOrDefault(account.getUuid(), Collections.emptySet());
        profile.setAchievements(playerAchs.stream()
            .map(achievements::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList()));

        // Get challenge completions
        Set<String> completedChallenges = playerChallenges.getOrDefault(account.getUuid(), Collections.emptySet());
        profile.setCompletedChallenges(completedChallenges.size());

        // Bounty points
        profile.setBountyPoints(playerBountyPoints.getOrDefault(account.getUuid(), 0));

        return profile;
    }

    /**
     * Update a player's profile display settings.
     */
    public void updateProfileSettings(UUID playerUuid, ProfileSettings settings) {
        PlayerProfile profile = profileCache.get(playerUuid);
        if (profile != null) {
            profile.setPublicProfile(settings.isPublicProfile());
            profile.setShowSecurityScore(settings.isShowSecurityScore());
            profile.setShowAchievements(settings.isShowAchievements());
        }

        auditService.log(AuditEventType.CUSTOM, playerUuid,
            platform.getPlayerName(playerUuid), platform.getPlayerIp(playerUuid),
            "profile-settings-updated");
    }

    // === Security Score ===

    /**
     * Calculate security score for an account.
     */
    public SecurityScore calculateSecurityScore(Account account) {
        int score = 0;
        List<String> improvements = new ArrayList<>();

        // Base score for having an account
        score += 10;

        // 2FA bonus (most important)
        if (account.getTwoFactorMethod() != TwoFactorMethod.NONE) {
            score += 30;
            if (account.getEnabledTwoFactorMethods().size() > 1) {
                score += 20; // Multiple 2FA methods
            }
        } else {
            improvements.add("Enable two-factor authentication (+30 points)");
        }

        // Account age bonus
        long accountAge = System.currentTimeMillis() - account.getCreatedAt().toEpochMilli();
        long accountAgeDays = accountAge / (1000 * 60 * 60 * 24);
        if (accountAgeDays > 365) {
            score += 15;
        } else if (accountAgeDays > 30) {
            score += 10;
        } else if (accountAgeDays > 7) {
            score += 5;
        }

        // No failed logins bonus
        if (account.getFailedLoginAttempts() == 0) {
            score += 15;
        } else if (account.getFailedLoginAttempts() < 3) {
            score += 5;
        } else {
            improvements.add("Review failed login attempts (+15 points possible)");
        }

        // Trusted devices bonus
        // Note: This would need to be fetched from storage

        // Achievements bonus
        Set<String> achs = playerAchievements.getOrDefault(account.getUuid(), Collections.emptySet());
        int achievementPoints = achs.stream()
            .map(id -> achievements.get(id))
            .filter(Objects::nonNull)
            .mapToInt(Achievement::getPoints)
            .sum();
        score += Math.min(achievementPoints / 2, 20); // Cap at 20

        // Cap score at 100
        score = Math.min(score, 100);

        // Determine grade
        String grade;
        if (score >= 90) grade = "A+";
        else if (score >= 80) grade = "A";
        else if (score >= 70) grade = "B";
        else if (score >= 60) grade = "C";
        else if (score >= 50) grade = "D";
        else grade = "F";

        return new SecurityScore(score, grade, improvements);
    }

    /**
     * Get security score for a player.
     */
    public SecurityScore getSecurityScore(UUID playerUuid) {
        return securityScores.computeIfAbsent(playerUuid, uuid -> {
            // This will be updated when profile is loaded
            return new SecurityScore(0, "N/A", Collections.emptyList());
        });
    }

    // === Leaderboard ===

    /**
     * Get the security leaderboard.
     */
    public List<LeaderboardEntry> getLeaderboard() {
        // Check cache
        if (System.currentTimeMillis() - lastLeaderboardUpdate < CACHE_TTL && !leaderboardCache.isEmpty()) {
            return new ArrayList<>(leaderboardCache);
        }

        // Rebuild leaderboard
        rebuildLeaderboard();
        return new ArrayList<>(leaderboardCache);
    }

    /**
     * Get leaderboard for a specific category.
     */
    public List<LeaderboardEntry> getLeaderboard(LeaderboardCategory category) {
        List<LeaderboardEntry> all = getLeaderboard();
        return all.stream()
            .filter(e -> e.getCategory() == category)
            .sorted((a, b) -> Integer.compare(b.getScore(), a.getScore()))
            .limit(MAX_LEADERBOARD_SIZE)
            .collect(Collectors.toList());
    }

    private void rebuildLeaderboard() {
        leaderboardCache.clear();

        for (Map.Entry<UUID, SecurityScore> entry : securityScores.entrySet()) {
            UUID uuid = entry.getKey();
            int score = entry.getValue().getScore();

            String name = platform.getPlayerName(uuid);
            if (name == null) name = "Unknown";

            leaderboardCache.add(new LeaderboardEntry(
                uuid, name, score, LeaderboardCategory.SECURITY_SCORE
            ));
        }

        // Sort by score descending
        leaderboardCache.sort((a, b) -> Integer.compare(b.getScore(), a.getScore()));

        // Limit size
        while (leaderboardCache.size() > MAX_LEADERBOARD_SIZE) {
            leaderboardCache.remove(leaderboardCache.size() - 1);
        }

        lastLeaderboardUpdate = System.currentTimeMillis();
    }

    /**
     * Get a player's rank on the leaderboard.
     */
    public int getPlayerRank(UUID playerUuid) {
        List<LeaderboardEntry> leaderboard = getLeaderboard();
        for (int i = 0; i < leaderboard.size(); i++) {
            if (leaderboard.get(i).getPlayerUuid().equals(playerUuid)) {
                return i + 1;
            }
        }
        return -1;
    }

    // === Achievements ===

    /**
     * Award an achievement to a player.
     */
    public boolean awardAchievement(UUID playerUuid, String achievementId) {
        Achievement achievement = achievements.get(achievementId);
        if (achievement == null) {
            return false;
        }

        Set<String> playerAchs = playerAchievements.computeIfAbsent(playerUuid, k -> ConcurrentHashMap.newKeySet());
        if (playerAchs.contains(achievementId)) {
            return false; // Already has it
        }

        playerAchs.add(achievementId);

        // Notify player
        String message = String.format("§6§lAchievement Unlocked!§r §e%s§r: %s",
            achievement.getName(), achievement.getDescription());
        platform.runSync(() -> platform.sendMessage(playerUuid, message));

        // Audit log
        auditService.log(AuditEventType.CUSTOM, playerUuid,
            platform.getPlayerName(playerUuid), platform.getPlayerIp(playerUuid),
            "achievement-unlocked: " + achievementId);

        logger.info("Achievement unlocked: " + achievementId + " for " + playerUuid);

        return true;
    }

    /**
     * Check and award achievements for a player.
     */
    public void checkAchievements(UUID playerUuid) {
        storage.getAccount(playerUuid).thenAccept(optAccount -> {
            if (optAccount.isEmpty()) return;

            Account account = optAccount.get();

            // Check 2FA achievement
            if (account.getTwoFactorMethod() != TwoFactorMethod.NONE) {
                awardAchievement(playerUuid, "first_2fa");
            }

            // Check multiple 2FA methods
            if (account.getEnabledTwoFactorMethods().size() >= 4) {
                awardAchievement(playerUuid, "2fa_master");
            }

            // Check no failed logins
            if (account.getFailedLoginAttempts() == 0) {
                // Check if account is old enough (30 days)
                long accountAge = System.currentTimeMillis() - account.getCreatedAt().toEpochMilli();
                if (accountAge > 30L * 24 * 60 * 60 * 1000) {
                    awardAchievement(playerUuid, "no_failed_logins");
                }
            }

            // Check account age achievements
            long accountAgeDays = (System.currentTimeMillis() - account.getCreatedAt().toEpochMilli()) / (1000 * 60 * 60 * 24);
            if (accountAgeDays >= 365) {
                awardAchievement(playerUuid, "account_1_year");
            }
            if (accountAgeDays >= 730) {
                awardAchievement(playerUuid, "account_2_years");
            }

            // Check challenge achievements
            Set<String> completed = playerChallenges.getOrDefault(playerUuid, Collections.emptySet());
            if (completed.size() >= 1) {
                awardAchievement(playerUuid, "security_challenge_1");
            }
            if (completed.size() >= 5) {
                awardAchievement(playerUuid, "security_challenge_5");
            }
        });
    }

    /**
     * Get all achievements.
     */
    public List<Achievement> getAllAchievements() {
        return new ArrayList<>(achievements.values());
    }

    /**
     * Get a player's achievements.
     */
    public List<Achievement> getPlayerAchievements(UUID playerUuid) {
        Set<String> playerAchs = playerAchievements.getOrDefault(playerUuid, Collections.emptySet());
        return playerAchs.stream()
            .map(achievements::get)
            .filter(Objects::nonNull)
            .sorted((a, b) -> Integer.compare(b.getPoints(), a.getPoints()))
            .collect(Collectors.toList());
    }

    // === Security Challenges ===

    /**
     * Get available security challenges.
     */
    public List<SecurityChallenge> getAvailableChallenges() {
        return Arrays.asList(
            new SecurityChallenge("challenge_1", "Password Master",
                "Create a password with strength score above 80",
                ChallengeType.PASSWORD, 50, 25, true),

            new SecurityChallenge("challenge_2", "2FA Champion",
                "Enable two different 2FA methods",
                ChallengeType.TWO_FA, 75, 30, true),

            new SecurityChallenge("challenge_3", "Security Audit",
                "Review and improve 3 security settings",
                ChallengeType.AUDIT, 60, 20, true),

            new SecurityChallenge("challenge_4", "Trusted Device",
                "Add and verify a trusted device",
                ChallengeType.TRUSTED_DEVICE, 40, 15, true),

            new SecurityChallenge("challenge_5", "Perfect Week",
                "No failed login attempts for 7 days",
                ChallengeType.STREAK, 100, 50, true),

            new SecurityChallenge("challenge_6", "Security Expert",
                "Achieve a security score of 90+",
                ChallengeType.SCORE, 150, 75, true)
        );
    }

    /**
     * Start a challenge for a player.
     */
    public boolean startChallenge(UUID playerUuid, String challengeId) {
        List<SecurityChallenge> challenges = getAvailableChallenges();
        SecurityChallenge challenge = challenges.stream()
            .filter(c -> c.getId().equals(challengeId))
            .findFirst()
            .orElse(null);

        if (challenge == null || !challenge.isActive()) {
            return false;
        }

        Set<String> playerChalls = playerChallenges.computeIfAbsent(playerUuid, k -> ConcurrentHashMap.newKeySet());
        if (playerChalls.contains(challengeId)) {
            return false; // Already completed
        }

        // Track progress
        challengeProgress.put(playerUuid, new ChallengeProgress(playerUuid, challengeId, System.currentTimeMillis()));

        platform.sendMessage(playerUuid, "§aChallenge started: §e" + challenge.getName());
        logger.info("Challenge started: " + challengeId + " for " + playerUuid);

        return true;
    }

    /**
     * Complete a challenge for a player.
     */
    public boolean completeChallenge(UUID playerUuid, String challengeId) {
        ChallengeProgress progress = challengeProgress.get(playerUuid);
        if (progress == null || !progress.getChallengeId().equals(challengeId)) {
            return false;
        }

        List<SecurityChallenge> challenges = getAvailableChallenges();
        SecurityChallenge challenge = challenges.stream()
            .filter(c -> c.getId().equals(challengeId))
            .findFirst()
            .orElse(null);

        if (challenge == null) {
            return false;
        }

        // Mark as completed
        Set<String> playerChalls = playerChallenges.computeIfAbsent(playerUuid, k -> ConcurrentHashMap.newKeySet());
        playerChalls.add(challengeId);

        // Remove progress
        challengeProgress.remove(playerUuid);

        // Award points
        playerBountyPoints.merge(playerUuid, challenge.getPoints(), Integer::sum);

        // Notify player
        platform.sendMessage(playerUuid, "§6§lChallenge Complete!§r §e" + challenge.getName() +
            "§r §a+" + challenge.getPoints() + " points");

        // Audit log
        auditService.log(AuditEventType.CUSTOM, playerUuid,
            platform.getPlayerName(playerUuid), platform.getPlayerIp(playerUuid),
            "challenge-completed: " + challengeId);

        // Check for achievement
        checkAchievements(playerUuid);

        return true;
    }

    /**
     * Get player's challenge progress.
     */
    public ChallengeProgress getChallengeProgress(UUID playerUuid) {
        return challengeProgress.get(playerUuid);
    }

    /**
     * Get player's completed challenges.
     */
    public List<SecurityChallenge> getCompletedChallenges(UUID playerUuid) {
        Set<String> completed = playerChallenges.getOrDefault(playerUuid, Collections.emptySet());
        return getAvailableChallenges().stream()
            .filter(c -> completed.contains(c.getId()))
            .collect(Collectors.toList());
    }

    // === Bug Bounty ===

    /**
     * Submit a bug bounty report.
     */
    public BugBountyResult submitBugReport(UUID playerUuid, BugBountyReport report) {
        // Validate report
        if (report.getTitle() == null || report.getTitle().isEmpty()) {
            return new BugBountyResult(false, null, "Title is required");
        }
        if (report.getDescription() == null || report.getDescription().isEmpty()) {
            return new BugBountyResult(false, null, "Description is required");
        }
        if (report.getSeverity() == null) {
            return new BugBountyResult(false, null, "Severity is required");
        }

        // Generate report ID
        String reportId = "BR-" + UUID.randomUUID().toString().substring(0, 8);

        // Set metadata
        report.setId(reportId);
        report.setReporterUuid(playerUuid);
        report.setReporterName(platform.getPlayerName(playerUuid));
        report.setSubmittedAt(System.currentTimeMillis());
        report.setStatus(BugBountyStatus.SUBMITTED);

        // Store report
        bugReports.put(reportId, report);

        // Audit log
        auditService.log(AuditEventType.CUSTOM, playerUuid,
            platform.getPlayerName(playerUuid), platform.getPlayerIp(playerUuid),
            "bug-report-submitted: " + reportId);

        logger.info("Bug report submitted: " + reportId + " by " + playerUuid);

        return new BugBountyResult(true, reportId, "Bug report submitted successfully. Thank you for helping improve security!");
    }

    /**
     * Get bug reports submitted by a player.
     */
    public List<BugBountyReport> getPlayerBugReports(UUID playerUuid) {
        return bugReports.values().stream()
            .filter(r -> r.getReporterUuid().equals(playerUuid))
            .sorted((a, b) -> Long.compare(b.getSubmittedAt(), a.getSubmittedAt()))
            .collect(Collectors.toList());
    }

    /**
     * Process a bug report (admin only).
     */
    public void processBugReport(String reportId, BugBountyStatus status, int awardedPoints, String adminNotes) {
        BugBountyReport report = bugReports.get(reportId);
        if (report == null) return;

        report.setStatus(status);
        report.setAdminNotes(adminNotes);
        report.setProcessedAt(System.currentTimeMillis());

        if (status == BugBountyStatus.ACCEPTED && awardedPoints > 0) {
            // Award points to reporter
            playerBountyPoints.merge(report.getReporterUuid(), awardedPoints, Integer::sum);

            // Award achievement
            awardAchievement(report.getReporterUuid(), "bug_hunter");

            // Notify player
            platform.sendMessage(report.getReporterUuid(),
                "§6§lBug Report Accepted!§r §a+" + awardedPoints + " bounty points");
        }

        logger.info("Bug report processed: " + reportId + " -> " + status);
    }

    /**
     * Get player's bounty points.
     */
    public int getBountyPoints(UUID playerUuid) {
        return playerBountyPoints.getOrDefault(playerUuid, 0);
    }

    // === Cleanup ===

    /**
     * Clean up expired data.
     */
    public void cleanup() {
        long now = System.currentTimeMillis();

        // Clean expired challenge progress (24 hours)
        challengeProgress.entrySet().removeIf(e ->
            now - e.getValue().getStartedAt() > 24 * 60 * 60 * 1000
        );

        logger.fine("Community service cleanup completed");
    }

    // === Data Classes ===

    public static class PlayerProfile {
        private final UUID playerUuid;
        private final String username;
        private final java.time.Instant createdAt;
        private final java.time.Instant lastLogin;
        private boolean has2FA;
        private Set<TwoFactorMethod> twoFactorMethods;
        private SecurityScore securityScore;
        private List<Achievement> achievements;
        private int completedChallenges;
        private int bountyPoints;
        private boolean publicProfile = true;
        private boolean showSecurityScore = true;
        private boolean showAchievements = true;

        public PlayerProfile(UUID playerUuid, String username, java.time.Instant createdAt, java.time.Instant lastLogin) {
            this.playerUuid = playerUuid;
            this.username = username;
            this.createdAt = createdAt;
            this.lastLogin = lastLogin;
        }

        // Getters and setters
        public UUID getPlayerUuid() { return playerUuid; }
        public String getUsername() { return username; }
        public java.time.Instant getCreatedAt() { return createdAt; }
        public java.time.Instant getLastLogin() { return lastLogin; }
        public boolean isHas2FA() { return has2FA; }
        public void setHas2FA(boolean has2FA) { this.has2FA = has2FA; }
        public Set<TwoFactorMethod> getTwoFactorMethods() { return twoFactorMethods; }
        public void setTwoFactorMethods(Set<TwoFactorMethod> methods) { this.twoFactorMethods = methods; }
        public SecurityScore getSecurityScore() { return securityScore; }
        public void setSecurityScore(SecurityScore score) { this.securityScore = score; }
        public List<Achievement> getAchievements() { return achievements; }
        public void setAchievements(List<Achievement> achievements) { this.achievements = achievements; }
        public int getCompletedChallenges() { return completedChallenges; }
        public void setCompletedChallenges(int count) { this.completedChallenges = count; }
        public int getBountyPoints() { return bountyPoints; }
        public void setBountyPoints(int points) { this.bountyPoints = points; }
        public boolean isPublicProfile() { return publicProfile; }
        public void setPublicProfile(boolean v) { this.publicProfile = v; }
        public boolean isShowSecurityScore() { return showSecurityScore; }
        public void setShowSecurityScore(boolean v) { this.showSecurityScore = v; }
        public boolean isShowAchievements() { return showAchievements; }
        public void setShowAchievements(boolean v) { this.showAchievements = v; }
    }

    public static class ProfileSettings {
        private boolean publicProfile = true;
        private boolean showSecurityScore = true;
        private boolean showAchievements = true;

        public boolean isPublicProfile() { return publicProfile; }
        public void setPublicProfile(boolean v) { this.publicProfile = v; }
        public boolean isShowSecurityScore() { return showSecurityScore; }
        public void setShowSecurityScore(boolean v) { this.showSecurityScore = v; }
        public boolean isShowAchievements() { return showAchievements; }
        public void setShowAchievements(boolean v) { this.showAchievements = v; }
    }

    public static class SecurityScore {
        private final int score;
        private final String grade;
        private final List<String> improvements;

        public SecurityScore(int score, String grade, List<String> improvements) {
            this.score = score;
            this.grade = grade;
            this.improvements = improvements;
        }

        public int getScore() { return score; }
        public String getGrade() { return grade; }
        public List<String> getImprovements() { return improvements; }
    }

    public static class LeaderboardEntry {
        private final UUID playerUuid;
        private final String playerName;
        private final int score;
        private final LeaderboardCategory category;

        public LeaderboardEntry(UUID playerUuid, String playerName, int score, LeaderboardCategory category) {
            this.playerUuid = playerUuid;
            this.playerName = playerName;
            this.score = score;
            this.category = category;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getPlayerName() { return playerName; }
        public int getScore() { return score; }
        public LeaderboardCategory getCategory() { return category; }
    }

    public enum LeaderboardCategory {
        SECURITY_SCORE,
        ACHIEVEMENTS,
        CHALLENGES,
        BOUNTY_POINTS
    }

    public static class Achievement {
        private final String id;
        private final String name;
        private final String description;
        private final AchievementType type;
        private final AchievementRarity rarity;
        private final int points;

        public Achievement(String id, String name, String description,
                          AchievementType type, AchievementRarity rarity, int points) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.type = type;
            this.rarity = rarity;
            this.points = points;
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public AchievementType getType() { return type; }
        public AchievementRarity getRarity() { return rarity; }
        public int getPoints() { return points; }
    }

    public enum AchievementType {
        SECURITY, CHALLENGE, SOCIAL, VETERAN, SPECIAL, CONTRIBUTION
    }

    public enum AchievementRarity {
        COMMON("§f", 1),
        UNCOMMON("§a", 2),
        RARE("§b", 3),
        EPIC("§d", 4),
        LEGENDARY("§6", 5);

        private final String color;
        private final int tier;

        AchievementRarity(String color, int tier) {
            this.color = color;
            this.tier = tier;
        }

        public String getColor() { return color; }
        public int getTier() { return tier; }
    }

    public static class SecurityChallenge {
        private final String id;
        private final String name;
        private final String description;
        private final ChallengeType type;
        private final int points;
        private final int experience;
        private final boolean active;

        public SecurityChallenge(String id, String name, String description,
                                 ChallengeType type, int points, int experience, boolean active) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.type = type;
            this.points = points;
            this.experience = experience;
            this.active = active;
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public ChallengeType getType() { return type; }
        public int getPoints() { return points; }
        public int getExperience() { return experience; }
        public boolean isActive() { return active; }
    }

    public enum ChallengeType {
        PASSWORD, TWO_FA, AUDIT, TRUSTED_DEVICE, STREAK, SCORE
    }

    public static class ChallengeProgress {
        private final UUID playerUuid;
        private final String challengeId;
        private final long startedAt;

        public ChallengeProgress(UUID playerUuid, String challengeId, long startedAt) {
            this.playerUuid = playerUuid;
            this.challengeId = challengeId;
            this.startedAt = startedAt;
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getChallengeId() { return challengeId; }
        public long getStartedAt() { return startedAt; }
    }

    public static class BugBountyReport {
        private String id;
        private String title;
        private String description;
        private BugBountySeverity severity;
        private String stepsToReproduce;
        private UUID reporterUuid;
        private String reporterName;
        private long submittedAt;
        private BugBountyStatus status;
        private String adminNotes;
        private long processedAt;

        // Getters and setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        public BugBountySeverity getSeverity() { return severity; }
        public void setSeverity(BugBountySeverity severity) { this.severity = severity; }
        public String getStepsToReproduce() { return stepsToReproduce; }
        public void setStepsToReproduce(String steps) { this.stepsToReproduce = steps; }
        public UUID getReporterUuid() { return reporterUuid; }
        public void setReporterUuid(UUID uuid) { this.reporterUuid = uuid; }
        public String getReporterName() { return reporterName; }
        public void setReporterName(String name) { this.reporterName = name; }
        public long getSubmittedAt() { return submittedAt; }
        public void setSubmittedAt(long time) { this.submittedAt = time; }
        public BugBountyStatus getStatus() { return status; }
        public void setStatus(BugBountyStatus status) { this.status = status; }
        public String getAdminNotes() { return adminNotes; }
        public void setAdminNotes(String notes) { this.adminNotes = notes; }
        public long getProcessedAt() { return processedAt; }
        public void setProcessedAt(long time) { this.processedAt = time; }
    }

    public enum BugBountySeverity {
        LOW(10), MEDIUM(25), HIGH(50), CRITICAL(100);

        private final int basePoints;

        BugBountySeverity(int basePoints) {
            this.basePoints = basePoints;
        }

        public int getBasePoints() { return basePoints; }
    }

    public enum BugBountyStatus {
        SUBMITTED, UNDER_REVIEW, ACCEPTED, REJECTED, DUPLICATE
    }

    public static class BugBountyResult {
        private final boolean success;
        private final String reportId;
        private final String message;

        public BugBountyResult(boolean success, String reportId, String message) {
            this.success = success;
            this.reportId = reportId;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getReportId() { return reportId; }
        public String getMessage() { return message; }
    }
}
