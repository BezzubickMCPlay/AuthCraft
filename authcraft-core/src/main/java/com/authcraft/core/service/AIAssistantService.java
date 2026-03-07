// com/authcraft/core/service/AIAssistantService.java
package com.authcraft.core.service;

import com.authcraft.core.api.PlatformAdapter;
import com.authcraft.core.api.StorageProvider;
import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.model.Account;
import com.authcraft.core.model.AuditEvent;
import com.authcraft.core.model.AuditEventType;
import com.authcraft.core.model.TwoFactorMethod;
import com.authcraft.core.security.SecurityRecommendation;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * AI-powered assistant service for player support and security recommendations.
 * Provides chatbot functionality, threat prediction, and smart suggestions.
 */
public class AIAssistantService {

    private final AuthCraftConfig config;
    private final StorageProvider storage;
    private final PlatformAdapter platform;
    private final AuditService auditService;
    private final Logger logger;

    // Knowledge base for chatbot responses
    private final Map<String, ChatbotResponse> knowledgeBase = new ConcurrentHashMap<>();
    private final Map<String, List<String>> intentPatterns = new ConcurrentHashMap<>();

    // Player conversation contexts
    private final Map<UUID, ConversationContext> conversations = new ConcurrentHashMap<>();

    // Security recommendation cache
    private final Map<UUID, List<SecurityRecommendation>> recommendationCache = new ConcurrentHashMap<>();
    private long lastRecommendationUpdate = 0;

    // Threat prediction model data
    private final Map<String, ThreatPattern> threatPatterns = new ConcurrentHashMap<>();
    private final List<ThreatIndicator> recentIndicators = Collections.synchronizedList(new ArrayList<>());

    // Password policy suggestions
    private final PasswordPolicyAnalyzer passwordAnalyzer;

    // Anomaly tracking
    private final Map<UUID, List<AnomalyRecord>> anomalyHistory = new ConcurrentHashMap<>();

    private static final long RECOMMENDATION_CACHE_TTL = 3600000; // 1 hour
    private static final int MAX_CONVERSATION_HISTORY = 20;
    private static final int MAX_ANOMALY_HISTORY = 50;

    public AIAssistantService(AuthCraftConfig config, StorageProvider storage,
                              PlatformAdapter platform, AuditService auditService) {
        this.config = config;
        this.storage = storage;
        this.platform = platform;
        this.auditService = auditService;
        this.logger = Logger.getLogger("AuthCraft-AI");
        this.passwordAnalyzer = new PasswordPolicyAnalyzer();

        initializeKnowledgeBase();
        initializeIntentPatterns();
        initializeThreatPatterns();
    }

    // === Initialization ===

    private void initializeKnowledgeBase() {
        // Authentication help
        knowledgeBase.put("auth_help", new ChatbotResponse(
            "I can help you with authentication! Here are common commands:\n" +
            "• /login <password> - Login to your account\n" +
            "• /register <password> - Create a new account\n" +
            "• /changepassword <old> <new> - Change your password\n" +
            "• /logout - Logout from your account",
            "auth"
        ));

        knowledgeBase.put("2fa_help", new ChatbotResponse(
            "Two-Factor Authentication (2FA) adds extra security to your account. " +
            "Available methods:\n" +
            "• TOTP (Google Authenticator, Authy)\n" +
            "• Telegram bot confirmation\n" +
            "• VK confirmation\n" +
            "Use /2fa enable <method> to set up 2FA.",
            "2fa"
        ));

        knowledgeBase.put("2fa_setup", new ChatbotResponse(
            "To set up 2FA:\n" +
            "1. Use /2fa enable <method> (totp, telegram, vk)\n" +
            "2. For TOTP: Scan the QR code with your authenticator app\n" +
            "3. Enter the code from your app to confirm\n" +
            "4. Save your backup codes in a safe place!",
            "2fa"
        ));

        knowledgeBase.put("2fa_lost", new ChatbotResponse(
            "If you lost access to your 2FA:\n" +
            "1. Check if you have backup codes\n" +
            "2. Contact a server administrator\n" +
            "3. Use /2fa backup if you have backup codes\n" +
            "Admins can reset 2FA with proper verification.",
            "2fa"
        ));

        knowledgeBase.put("password_help", new ChatbotResponse(
            "Password requirements:\n" +
            "• Minimum 8 characters\n" +
            "• At least one uppercase letter\n" +
            "• At least one lowercase letter\n" +
            "• At least one number\n" +
            "• Avoid common passwords and sequences\n" +
            "Use a password manager for best security!",
            "password"
        ));

        knowledgeBase.put("account_security", new ChatbotResponse(
            "To secure your account:\n" +
            "1. Use a strong, unique password\n" +
            "2. Enable 2FA immediately\n" +
            "3. Never share your password\n" +
            "4. Be careful of phishing attempts\n" +
            "5. Report suspicious activity to admins",
            "security"
        ));

        knowledgeBase.put("session_help", new ChatbotResponse(
            "Session management:\n" +
            "• Your session lasts 7 days by default\n" +
            "• Use /logout to end your session\n" +
            "• Sessions are IP-bound for security\n" +
            "• Contact admin if you see unknown logins",
            "session"
        ));

        knowledgeBase.put("trusted_device", new ChatbotResponse(
            "Trusted device feature:\n" +
            "• Skip 2FA on trusted devices\n" +
            "• Use /trust to mark current device\n" +
            "• Max 5 trusted devices per account\n" +
            "• Devices expire after 30 days\n" +
            "• Use /untrust to remove devices",
            "trusted"
        ));

        knowledgeBase.put("greeting", new ChatbotResponse(
            "Hello! I'm the AuthCraft security assistant. " +
            "I can help you with:\n" +
            "• Account authentication\n" +
            "• Two-factor authentication setup\n" +
            "• Password security\n" +
            "• Account recovery\n" +
            "• Security recommendations\n\n" +
            "What would you like help with?",
            "general"
        ));

        knowledgeBase.put("unknown", new ChatbotResponse(
            "I'm not sure I understand. Could you rephrase that?\n" +
            "You can ask about:\n" +
            "• How to login or register\n" +
            "• Setting up 2FA\n" +
            "• Password requirements\n" +
            "• Account security tips\n" +
            "• Recovering your account",
            "general"
        ));

        knowledgeBase.put("security_tips", new ChatbotResponse(
            "Here are my top security tips:\n" +
            "1. Use unique passwords for each server\n" +
            "2. Enable 2FA on all accounts\n" +
            "3. Keep your email account secure\n" +
            "4. Don't click suspicious links\n" +
            "5. Report phishing attempts\n" +
            "6. Use a password manager\n" +
            "7. Keep your Minecraft client updated",
            "security"
        ));
    }

    private void initializeIntentPatterns() {
        // Authentication intents
        intentPatterns.put("auth_help", Arrays.asList(
            "how do i login", "how to login", "login help", "cant login",
            "how do i register", "how to register", "register help",
            "authentication", "auth help", "sign in", "sign up"
        ));

        // 2FA intents
        intentPatterns.put("2fa_help", Arrays.asList(
            "what is 2fa", "two factor", "2fa help", "two-factor",
            "authenticator", "totp", "verification"
        ));

        intentPatterns.put("2fa_setup", Arrays.asList(
            "how to enable 2fa", "setup 2fa", "enable 2fa", "2fa setup",
            "how to set up 2fa", "add 2fa", "turn on 2fa"
        ));

        intentPatterns.put("2fa_lost", Arrays.asList(
            "lost 2fa", "lost authenticator", "cant access 2fa",
            "2fa not working", "lost backup codes", "reset 2fa",
            "forgot 2fa", "2fa locked out"
        ));

        // Password intents
        intentPatterns.put("password_help", Arrays.asList(
            "password requirements", "password help", "strong password",
            "password rules", "password policy", "what password"
        ));

        // Security intents
        intentPatterns.put("account_security", Arrays.asList(
            "secure my account", "account security", "how to be safe",
            "protect account", "security tips", "stay safe"
        ));

        intentPatterns.put("security_tips", Arrays.asList(
            "security tips", "security advice", "best practices",
            "how to stay safe", "security recommendations"
        ));

        // Session intents
        intentPatterns.put("session_help", Arrays.asList(
            "session", "how long", "stay logged in", "keep me logged",
            "logout", "session expired"
        ));

        // Trusted device intents
        intentPatterns.put("trusted_device", Arrays.asList(
            "trusted device", "remember device", "trust this device",
            "skip 2fa", "dont ask again"
        ));

        // Greeting intents
        intentPatterns.put("greeting", Arrays.asList(
            "hello", "hi", "hey", "help", "start", "begin"
        ));
    }

    private void initializeThreatPatterns() {
        // Brute force patterns
        threatPatterns.put("brute_force", new ThreatPattern(
            "brute_force",
            0.8,
            Arrays.asList("multiple_failed_logins", "rapid_attempts", "sequential_passwords"),
            "Multiple failed login attempts detected from same source"
        ));

        // Credential stuffing
        threatPatterns.put("credential_stuffing", new ThreatPattern(
            "credential_stuffing",
            0.75,
            Arrays.asList("known_breached_passwords", "automated_behavior", "distributed_attempts"),
            "Credential stuffing attack detected - using known breached credentials"
        ));

        // Account takeover
        threatPatterns.put("account_takeover", new ThreatPattern(
            "account_takeover",
            0.85,
            Arrays.asList("new_location", "new_device", "password_change", "2fa_disabled"),
            "Potential account takeover - suspicious activity pattern"
        ));

        // Bot behavior
        threatPatterns.put("bot_behavior", new ThreatPattern(
            "bot_behavior",
            0.7,
            Arrays.asList("fast_responses", "pattern_timing", "inhuman_speed"),
            "Bot-like behavior detected"
        ));

        // VPN/Proxy abuse
        threatPatterns.put("proxy_abuse", new ThreatPattern(
            "proxy_abuse",
            0.65,
            Arrays.asList("vpn_ip", "multiple_accounts", "tor_exit_node"),
            "VPN/Proxy abuse detected - multiple accounts from same IP"
        ));
    }

    // === AI Chatbot ===

    /**
     * Process a player's message and generate a response.
     */
    public ChatResponse processMessage(UUID playerUuid, String message) {
        // Get or create conversation context
        ConversationContext context = conversations.computeIfAbsent(playerUuid,
            k -> new ConversationContext(playerUuid));

        // Add message to history
        context.addMessage(message, true);

        // Detect intent
        String intent = detectIntent(message.toLowerCase().trim());

        // Get response from knowledge base
        ChatbotResponse response = knowledgeBase.getOrDefault(intent, knowledgeBase.get("unknown"));

        // Check for context-aware responses
        String contextResponse = getContextAwareResponse(context, intent, message);
        if (contextResponse != null) {
            response = new ChatbotResponse(contextResponse, response.getCategory());
        }

        // Add response to history
        context.addMessage(response.getMessage(), false);

        // Track interaction
        auditService.log(AuditEventType.CUSTOM, playerUuid,
            platform.getPlayerName(playerUuid), platform.getPlayerIp(playerUuid),
            "ai-chatbot-interaction: " + intent);

        return new ChatResponse(response.getMessage(), intent, context.getConversationId());
    }

    private String detectIntent(String message) {
        for (Map.Entry<String, List<String>> entry : intentPatterns.entrySet()) {
            for (String pattern : entry.getValue()) {
                if (message.contains(pattern)) {
                    return entry.getKey();
                }
            }
        }

        // Fuzzy matching for partial matches
        for (Map.Entry<String, List<String>> entry : intentPatterns.entrySet()) {
            for (String pattern : entry.getValue()) {
                String[] words = pattern.split(" ");
                int matchCount = 0;
                for (String word : words) {
                    if (message.contains(word)) {
                        matchCount++;
                    }
                }
                if (matchCount >= Math.ceil(words.length * 0.6)) {
                    return entry.getKey();
                }
            }
        }

        return "unknown";
    }

    private String getContextAwareResponse(ConversationContext context, String intent, String message) {
        // Check conversation history for context
        List<MessageRecord> history = context.getHistory();
        if (history.size() > 1) {
            MessageRecord lastMessage = history.get(history.size() - 2);
            if (!lastMessage.isFromPlayer()) {
                // Player is responding to our last message
                String lastCategory = extractCategory(lastMessage.getContent());

                // Handle follow-up questions
                if (lastCategory.equals("2fa") && intent.equals("unknown")) {
                    if (message.contains("backup") || message.contains("code")) {
                        return "Backup codes are shown once when you enable 2FA. " +
                               "If you've lost them, you'll need to contact an administrator " +
                               "to reset your 2FA. Would you like to know how to contact an admin?";
                    }
                }

                if (lastCategory.equals("password") && intent.equals("unknown")) {
                    if (message.contains("manager") || message.contains("app")) {
                        return "Popular password managers include:\n" +
                               "• Bitwarden (free, open source)\n" +
                               "• LastPass\n" +
                               "• 1Password\n" +
                               "• KeePass (offline)\n" +
                               "These help you create and store strong, unique passwords.";
                    }
                }
            }
        }

        // Check for account-specific context
        UUID playerUuid = context.getPlayerUuid();
        if (intent.equals("account_security")) {
            return generatePersonalizedSecurityAdvice(playerUuid);
        }

        return null;
    }

    private String extractCategory(String message) {
        for (ChatbotResponse response : knowledgeBase.values()) {
            if (response.getMessage().equals(message)) {
                return response.getCategory();
            }
        }
        return "general";
    }

    private String generatePersonalizedSecurityAdvice(UUID playerUuid) {
        StringBuilder advice = new StringBuilder("Based on your account:\n");

        storage.getAccount(playerUuid).thenAccept(optAccount -> {
            if (optAccount.isPresent()) {
                Account account = optAccount.get();

                if (account.getTwoFactorMethod() == TwoFactorMethod.NONE) {
                    advice.append("• Enable 2FA - you don't have it set up!\n");
                }

                if (account.getFailedLoginAttempts() > 0) {
                    advice.append("• You have ").append(account.getFailedLoginAttempts())
                          .append(" failed login attempts - check for suspicious activity\n");
                }
            }
        });

        return advice.toString();
    }

    // === Security Recommendations ===

    /**
     * Generate security recommendations for a player.
     */
    public List<SecurityRecommendation> getSecurityRecommendations(UUID playerUuid) {
        // Check cache
        if (System.currentTimeMillis() - lastRecommendationUpdate < RECOMMENDATION_CACHE_TTL) {
            return recommendationCache.getOrDefault(playerUuid, Collections.emptyList());
        }

        List<SecurityRecommendation> recommendations = new ArrayList<>();

        storage.getAccount(playerUuid).thenAccept(optAccount -> {
            if (optAccount.isEmpty()) {
                return;
            }

            Account account = optAccount.get();

            // Check 2FA status
            if (account.getTwoFactorMethod() == TwoFactorMethod.NONE) {
                recommendations.add(new SecurityRecommendation(
                    "enable_2fa",
                    "HIGH",
                    "Enable Two-Factor Authentication",
                    "Your account doesn't have 2FA enabled. This is a critical security measure.",
                    "/2fa enable totp",
                    100
                ));
            }

            // Check password age
            long passwordAge = System.currentTimeMillis() - account.getCreatedAt().toEpochMilli();
            long passwordAgeDays = passwordAge / (1000 * 60 * 60 * 24);
            if (passwordAgeDays > 90) {
                recommendations.add(new SecurityRecommendation(
                    "change_password",
                    "MEDIUM",
                    "Update Your Password",
                    "Your password is over 90 days old. Consider updating it.",
                    "/changepassword",
                    70
                ));
            }

            // Check failed login attempts
            if (account.getFailedLoginAttempts() > 0) {
                recommendations.add(new SecurityRecommendation(
                    "check_login_attempts",
                    "MEDIUM",
                    "Review Recent Login Attempts",
                    "You have " + account.getFailedLoginAttempts() + " failed login attempts.",
                    "Check your email for security alerts",
                    60
                ));
            }

            // Check trusted devices
            storage.getTrustedDevices(playerUuid).thenAccept(devices -> {
                if (devices.size() >= 4) {
                    recommendations.add(new SecurityRecommendation(
                        "review_trusted_devices",
                        "LOW",
                        "Review Trusted Devices",
                        "You have " + devices.size() + " trusted devices. Consider removing unused ones.",
                        "/2fa devices",
                        40
                    ));
                }
            });

            // Sort by priority
            recommendations.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));

            // Cache results
            recommendationCache.put(playerUuid, recommendations);
        });

        return recommendations;
    }

    /**
     * Generate server-wide security recommendations.
     */
    public List<SecurityRecommendation> getServerSecurityRecommendations() {
        List<SecurityRecommendation> recommendations = new ArrayList<>();

        // Check 2FA adoption rate
        storage.countAccountsWith2FA().thenAccept(twoFactorCount -> {
            storage.countTotalAccounts().thenAccept(totalCount -> {
                double adoptionRate = totalCount > 0 ? (double) twoFactorCount / totalCount : 0;
                if (adoptionRate < 0.5) {
                    recommendations.add(new SecurityRecommendation(
                        "server_2fa_adoption",
                        "HIGH",
                        "Low 2FA Adoption Rate",
                        String.format("Only %.1f%% of players have 2FA enabled. Target: 50%%+", adoptionRate * 100),
                        "Consider requiring 2FA for staff or high-value accounts",
                        90
                    ));
                }
            });
        });

        // Check recent failed logins
        long recentThreshold = System.currentTimeMillis() - (24 * 60 * 60 * 1000);
        storage.countRecentFailedLogins(recentThreshold).thenAccept(failedCount -> {
            if (failedCount > 100) {
                recommendations.add(new SecurityRecommendation(
                    "server_failed_logins",
                    "MEDIUM",
                    "High Failed Login Rate",
                    failedCount + " failed logins in the last 24 hours",
                    "Review security logs and consider IP blocking",
                    70
                ));
            }
        });

        return recommendations;
    }

    // === Predictive Threat Detection ===

    /**
     * Analyze current threat indicators and predict potential attacks.
     */
    public ThreatPrediction analyzeThreats() {
        ThreatPrediction prediction = new ThreatPrediction();

        // Analyze recent indicators
        synchronized (recentIndicators) {
            for (ThreatIndicator indicator : recentIndicators) {
                for (ThreatPattern pattern : threatPatterns.values()) {
                    if (pattern.getIndicators().contains(indicator.getType())) {
                        prediction.addMatch(pattern, indicator);
                    }
                }
            }
        }

        // Calculate threat scores
        for (Map.Entry<String, Double> entry : prediction.getMatchScores().entrySet()) {
            ThreatPattern pattern = threatPatterns.get(entry.getKey());
            if (pattern != null) {
                double score = entry.getValue() * pattern.getWeight();
                prediction.addThreatScore(entry.getKey(), score);
            }
        }

        // Generate predictions
        if (prediction.getOverallThreatScore() > 0.7) {
            prediction.setPrediction("High probability of ongoing attack detected");
            prediction.setConfidence(prediction.getOverallThreatScore());
            prediction.addRecommendation("Enable enhanced monitoring mode");
            prediction.addRecommendation("Review recent failed login attempts");
            prediction.addRecommendation("Consider temporary IP blocking");
        } else if (prediction.getOverallThreatScore() > 0.4) {
            prediction.setPrediction("Elevated threat level detected");
            prediction.setConfidence(prediction.getOverallThreatScore());
            prediction.addRecommendation("Monitor authentication logs closely");
            prediction.addRecommendation("Verify 2FA policies are enforced");
        } else {
            prediction.setPrediction("Normal threat level");
            prediction.setConfidence(1.0 - prediction.getOverallThreatScore());
        }

        return prediction;
    }

    /**
     * Add a threat indicator for analysis.
     */
    public void addThreatIndicator(ThreatIndicator indicator) {
        recentIndicators.add(indicator);

        // Keep only recent indicators (last 1000)
        while (recentIndicators.size() > 1000) {
            recentIndicators.remove(0);
        }

        // Log significant indicators
        if (indicator.getSeverity() > 0.7) {
            logger.warning("High severity threat indicator: " + indicator.getType() +
                          " from " + indicator.getSource());
        }
    }

    // === Smart Password Policy Suggestions ===

    /**
     * Analyze password policy and suggest improvements.
     */
    public PasswordPolicyAnalysis analyzePasswordPolicy() {
        PasswordPolicyAnalysis analysis = new PasswordPolicyAnalysis();

        // Current policy
        analysis.setCurrentMinLength(config.getPasswordMinLength());
        analysis.setCurrentRequireUppercase(config.isPasswordRequireUppercase());
        analysis.setCurrentRequireLowercase(config.isPasswordRequireLowercase());
        analysis.setCurrentRequireDigit(config.isPasswordRequireDigit());
        analysis.setCurrentRequireSpecial(config.isPasswordRequireSpecial());
        analysis.setCurrentMinScore(config.getPasswordMinScore());

        // Calculate policy strength
        int policyScore = 0;
        if (config.getPasswordMinLength() >= 8) policyScore += 20;
        if (config.getPasswordMinLength() >= 12) policyScore += 10;
        if (config.isPasswordRequireUppercase()) policyScore += 15;
        if (config.isPasswordRequireLowercase()) policyScore += 15;
        if (config.isPasswordRequireDigit()) policyScore += 15;
        if (config.isPasswordRequireSpecial()) policyScore += 15;
        if (config.isPasswordCheckBlacklist()) policyScore += 10;
        if (config.isPasswordCheckSequences()) policyScore += 10;
        if (config.getPasswordMinScore() >= 50) policyScore += 10;

        analysis.setPolicyScore(policyScore);

        // Generate suggestions
        if (config.getPasswordMinLength() < 12) {
            analysis.addSuggestion(new PolicySuggestion(
                "min_length",
                "Increase minimum password length to 12 characters",
                "Longer passwords are exponentially harder to crack",
                "HIGH",
                15
            ));
        }

        if (!config.isPasswordRequireSpecial()) {
            analysis.addSuggestion(new PolicySuggestion(
                "require_special",
                "Require special characters in passwords",
                "Special characters significantly increase password entropy",
                "MEDIUM",
                12
            ));
        }

        if (!config.isPasswordCheckBlacklist()) {
            analysis.addSuggestion(new PolicySuggestion(
                "check_blacklist",
                "Enable password blacklist checking",
                "Prevents use of commonly breached passwords",
                "HIGH",
                20
            ));
        }

        if (config.getPasswordMinScore() < 60) {
            analysis.addSuggestion(new PolicySuggestion(
                "min_score",
                "Increase minimum password strength score to 60",
                "Ensures passwords meet minimum entropy requirements",
                "MEDIUM",
                10
            ));
        }

        return analysis;
    }

    /**
     * Get password strength suggestions for a specific password.
     */
    public List<String> getPasswordSuggestions(String password, String username) {
        return passwordAnalyzer.analyze(password, username);
    }

    // === Anomaly Explanation Reports ===

    /**
     * Generate an anomaly explanation report for a player.
     */
    public AnomalyReport generateAnomalyReport(UUID playerUuid) {
        AnomalyReport report = new AnomalyReport(playerUuid);

        // Get recent anomalies for this player
        List<AnomalyRecord> anomalies = anomalyHistory.getOrDefault(playerUuid, Collections.emptyList());

        for (AnomalyRecord anomaly : anomalies) {
            report.addAnomaly(anomaly);

            // Generate explanation
            String explanation = generateAnomalyExplanation(anomaly);
            report.addExplanation(anomaly.getId(), explanation);

            // Generate recommendations
            List<String> recommendations = generateAnomalyRecommendations(anomaly);
            report.addRecommendations(anomaly.getId(), recommendations);
        }

        // Calculate overall risk score
        double riskScore = calculateRiskScore(anomalies);
        report.setRiskScore(riskScore);
        report.setRiskLevel(getRiskLevel(riskScore));

        // Generate summary
        report.setSummary(generateReportSummary(report));

        return report;
    }

    private String generateAnomalyExplanation(AnomalyRecord anomaly) {
        switch (anomaly.getType()) {
            case "new_location":
                return "A login was detected from a new geographic location. " +
                       "This could indicate legitimate travel or potential unauthorized access.";
            case "new_device":
                return "A login was detected from a new device. " +
                       "If you recently got a new device, this is expected. " +
                       "Otherwise, investigate this activity.";
            case "unusual_time":
                return "Login occurred at an unusual time for this account. " +
                       "Consider whether this matches your typical usage patterns.";
            case "multiple_failed_attempts":
                return "Multiple failed login attempts were detected. " +
                       "This could be you forgetting your password, or someone trying to guess it.";
            case "password_spray":
                return "Your account was targeted in a password spray attack. " +
                       "The attacker tried common passwords across many accounts.";
            case "credential_stuffing":
                return "Your credentials may have been exposed in a data breach. " +
                       "Attackers are testing known breached credentials.";
            default:
                return "An unusual activity pattern was detected on your account.";
        }
    }

    private List<String> generateAnomalyRecommendations(AnomalyRecord anomaly) {
        List<String> recommendations = new ArrayList<>();

        switch (anomaly.getType()) {
            case "new_location":
            case "new_device":
                recommendations.add("Verify this was you by checking your email for login alerts");
                recommendations.add("If unrecognized, change your password immediately");
                recommendations.add("Enable 2FA if not already active");
                break;
            case "multiple_failed_attempts":
                recommendations.add("Change your password if you didn't make these attempts");
                recommendations.add("Enable 2FA for additional protection");
                recommendations.add("Consider using a stronger password");
                break;
            case "credential_stuffing":
                recommendations.add("Change your password immediately");
                recommendations.add("Use a unique password not used on other services");
                recommendations.add("Enable 2FA");
                recommendations.add("Check if your email was breached at haveibeenpwned.com");
                break;
            default:
                recommendations.add("Monitor your account for suspicious activity");
                recommendations.add("Enable 2FA for additional security");
        }

        return recommendations;
    }

    private double calculateRiskScore(List<AnomalyRecord> anomalies) {
        if (anomalies.isEmpty()) return 0.0;

        double totalScore = 0.0;
        for (AnomalyRecord anomaly : anomalies) {
            totalScore += anomaly.getSeverity();
        }

        return Math.min(1.0, totalScore / anomalies.size());
    }

    private String getRiskLevel(double riskScore) {
        if (riskScore >= 0.7) return "HIGH";
        if (riskScore >= 0.4) return "MEDIUM";
        return "LOW";
    }

    private String generateReportSummary(AnomalyReport report) {
        int anomalyCount = report.getAnomalies().size();
        String riskLevel = report.getRiskLevel();

        if (anomalyCount == 0) {
            return "No security anomalies detected. Your account appears to be secure.";
        }

        return String.format(
            "Detected %d security anomalies with %s risk level. " +
            "Please review the details and follow the recommendations to secure your account.",
            anomalyCount, riskLevel
        );
    }

    /**
     * Record an anomaly for a player.
     */
    public void recordAnomaly(UUID playerUuid, String type, String description, double severity) {
        AnomalyRecord anomaly = new AnomalyRecord(
            UUID.randomUUID().toString(),
            playerUuid,
            type,
            description,
            severity,
            System.currentTimeMillis()
        );

        anomalyHistory.computeIfAbsent(playerUuid, k -> Collections.synchronizedList(new ArrayList<>()))
            .add(anomaly);

        // Keep only recent anomalies
        List<AnomalyRecord> records = anomalyHistory.get(playerUuid);
        while (records.size() > MAX_ANOMALY_HISTORY) {
            records.remove(0);
        }

        // Log significant anomalies
        if (severity > 0.7) {
            logger.warning("High severity anomaly for " + playerUuid + ": " + description);
            auditService.log(AuditEventType.CUSTOM, playerUuid,
                platform.getPlayerName(playerUuid), platform.getPlayerIp(playerUuid),
                "anomaly-detected: " + type + " - " + description);
        }
    }

    // === Cleanup ===

    /**
     * Clean up old conversation contexts and cached data.
     */
    public void cleanup() {
        long now = System.currentTimeMillis();
        long maxAge = 3600000; // 1 hour

        // Clean old conversations
        conversations.entrySet().removeIf(entry ->
            now - entry.getValue().getLastActivity() > maxAge
        );

        // Clean old threat indicators
        synchronized (recentIndicators) {
            recentIndicators.removeIf(indicator ->
                now - indicator.getTimestamp() > maxAge
            );
        }

        logger.fine("AI assistant cleanup completed");
    }

    // === Data Classes ===

    public static class ChatResponse {
        private final String message;
        private final String intent;
        private final String conversationId;

        public ChatResponse(String message, String intent, String conversationId) {
            this.message = message;
            this.intent = intent;
            this.conversationId = conversationId;
        }

        public String getMessage() { return message; }
        public String getIntent() { return intent; }
        public String getConversationId() { return conversationId; }
    }

    public static class ChatbotResponse {
        private final String message;
        private final String category;

        public ChatbotResponse(String message, String category) {
            this.message = message;
            this.category = category;
        }

        public String getMessage() { return message; }
        public String getCategory() { return category; }
    }

    public static class ConversationContext {
        private final UUID playerUuid;
        private final String conversationId;
        private final List<MessageRecord> history;
        private long lastActivity;

        public ConversationContext(UUID playerUuid) {
            this.playerUuid = playerUuid;
            this.conversationId = UUID.randomUUID().toString();
            this.history = new ArrayList<>();
            this.lastActivity = System.currentTimeMillis();
        }

        public void addMessage(String content, boolean fromPlayer) {
            history.add(new MessageRecord(content, fromPlayer, System.currentTimeMillis()));
            lastActivity = System.currentTimeMillis();

            // Limit history size
            while (history.size() > MAX_CONVERSATION_HISTORY) {
                history.remove(0);
            }
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public String getConversationId() { return conversationId; }
        public List<MessageRecord> getHistory() { return new ArrayList<>(history); }
        public long getLastActivity() { return lastActivity; }
    }

    public static class MessageRecord {
        private final String content;
        private final boolean fromPlayer;
        private final long timestamp;

        public MessageRecord(String content, boolean fromPlayer, long timestamp) {
            this.content = content;
            this.fromPlayer = fromPlayer;
            this.timestamp = timestamp;
        }

        public String getContent() { return content; }
        public boolean isFromPlayer() { return fromPlayer; }
        public long getTimestamp() { return timestamp; }
    }

    public static class ThreatPattern {
        private final String name;
        private final double weight;
        private final List<String> indicators;
        private final String description;

        public ThreatPattern(String name, double weight, List<String> indicators, String description) {
            this.name = name;
            this.weight = weight;
            this.indicators = indicators;
            this.description = description;
        }

        public String getName() { return name; }
        public double getWeight() { return weight; }
        public List<String> getIndicators() { return indicators; }
        public String getDescription() { return description; }
    }

    public static class ThreatIndicator {
        private final String type;
        private final String source;
        private final double severity;
        private final long timestamp;
        private final Map<String, Object> metadata;

        public ThreatIndicator(String type, String source, double severity, Map<String, Object> metadata) {
            this.type = type;
            this.source = source;
            this.severity = severity;
            this.timestamp = System.currentTimeMillis();
            this.metadata = metadata != null ? metadata : new HashMap<>();
        }

        public String getType() { return type; }
        public String getSource() { return source; }
        public double getSeverity() { return severity; }
        public long getTimestamp() { return timestamp; }
        public Map<String, Object> getMetadata() { return metadata; }
    }

    public static class ThreatPrediction {
        private final Map<String, List<ThreatIndicator>> matches = new HashMap<>();
        private final Map<String, Double> matchScores = new HashMap<>();
        private final Map<String, Double> threatScores = new HashMap<>();
        private final List<String> recommendations = new ArrayList<>();
        private String prediction;
        private double confidence;

        public void addMatch(ThreatPattern pattern, ThreatIndicator indicator) {
            matches.computeIfAbsent(pattern.getName(), k -> new ArrayList<>()).add(indicator);
            matchScores.merge(pattern.getName(), indicator.getSeverity(), Double::sum);
        }

        public void addThreatScore(String pattern, double score) {
            threatScores.put(pattern, score);
        }

        public void addRecommendation(String recommendation) {
            recommendations.add(recommendation);
        }

        public double getOverallThreatScore() {
            return threatScores.values().stream().mapToDouble(Double::doubleValue).max().orElse(0.0);
        }

        public Map<String, List<ThreatIndicator>> getMatches() { return matches; }
        public Map<String, Double> getMatchScores() { return matchScores; }
        public Map<String, Double> getThreatScores() { return threatScores; }
        public List<String> getRecommendations() { return recommendations; }
        public String getPrediction() { return prediction; }
        public void setPrediction(String prediction) { this.prediction = prediction; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
    }

    public static class AnomalyRecord {
        private final String id;
        private final UUID playerUuid;
        private final String type;
        private final String description;
        private final double severity;
        private final long timestamp;

        public AnomalyRecord(String id, UUID playerUuid, String type, String description, double severity, long timestamp) {
            this.id = id;
            this.playerUuid = playerUuid;
            this.type = type;
            this.description = description;
            this.severity = severity;
            this.timestamp = timestamp;
        }

        public String getId() { return id; }
        public UUID getPlayerUuid() { return playerUuid; }
        public String getType() { return type; }
        public String getDescription() { return description; }
        public double getSeverity() { return severity; }
        public long getTimestamp() { return timestamp; }
    }

    public static class AnomalyReport {
        private final UUID playerUuid;
        private final List<AnomalyRecord> anomalies = new ArrayList<>();
        private final Map<String, String> explanations = new HashMap<>();
        private final Map<String, List<String>> recommendations = new HashMap<>();
        private double riskScore;
        private String riskLevel;
        private String summary;

        public AnomalyReport(UUID playerUuid) {
            this.playerUuid = playerUuid;
        }

        public void addAnomaly(AnomalyRecord anomaly) { anomalies.add(anomaly); }
        public void addExplanation(String anomalyId, String explanation) {
            explanations.put(anomalyId, explanation);
        }
        public void addRecommendations(String anomalyId, List<String> recs) {
            recommendations.put(anomalyId, recs);
        }

        public UUID getPlayerUuid() { return playerUuid; }
        public List<AnomalyRecord> getAnomalies() { return anomalies; }
        public Map<String, String> getExplanations() { return explanations; }
        public Map<String, List<String>> getRecommendations() { return recommendations; }
        public double getRiskScore() { return riskScore; }
        public void setRiskScore(double riskScore) { this.riskScore = riskScore; }
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
    }

    public static class PasswordPolicyAnalysis {
        private int currentMinLength;
        private boolean currentRequireUppercase;
        private boolean currentRequireLowercase;
        private boolean currentRequireDigit;
        private boolean currentRequireSpecial;
        private int currentMinScore;
        private int policyScore;
        private final List<PolicySuggestion> suggestions = new ArrayList<>();

        // Getters and setters
        public int getCurrentMinLength() { return currentMinLength; }
        public void setCurrentMinLength(int v) { this.currentMinLength = v; }
        public boolean isCurrentRequireUppercase() { return currentRequireUppercase; }
        public void setCurrentRequireUppercase(boolean v) { this.currentRequireUppercase = v; }
        public boolean isCurrentRequireLowercase() { return currentRequireLowercase; }
        public void setCurrentRequireLowercase(boolean v) { this.currentRequireLowercase = v; }
        public boolean isCurrentRequireDigit() { return currentRequireDigit; }
        public void setCurrentRequireDigit(boolean v) { this.currentRequireDigit = v; }
        public boolean isCurrentRequireSpecial() { return currentRequireSpecial; }
        public void setCurrentRequireSpecial(boolean v) { this.currentRequireSpecial = v; }
        public int getCurrentMinScore() { return currentMinScore; }
        public void setCurrentMinScore(int v) { this.currentMinScore = v; }
        public int getPolicyScore() { return policyScore; }
        public void setPolicyScore(int v) { this.policyScore = v; }
        public List<PolicySuggestion> getSuggestions() { return suggestions; }
        public void addSuggestion(PolicySuggestion s) { suggestions.add(s); }
    }

    public static class PolicySuggestion {
        private final String id;
        private final String suggestion;
        private final String rationale;
        private final String priority;
        private final int impact;

        public PolicySuggestion(String id, String suggestion, String rationale, String priority, int impact) {
            this.id = id;
            this.suggestion = suggestion;
            this.rationale = rationale;
            this.priority = priority;
            this.impact = impact;
        }

        public String getId() { return id; }
        public String getSuggestion() { return suggestion; }
        public String getRationale() { return rationale; }
        public String getPriority() { return priority; }
        public int getImpact() { return impact; }
    }

    /**
     * Password policy analyzer for generating smart suggestions.
     */
    private static class PasswordPolicyAnalyzer {

        public List<String> analyze(String password, String username) {
            List<String> suggestions = new ArrayList<>();

            // Length analysis
            if (password.length() < 8) {
                suggestions.add("Password is too short. Use at least 8 characters.");
            } else if (password.length() < 12) {
                suggestions.add("Consider using 12+ characters for better security.");
            }

            // Character variety
            if (!password.matches(".*[A-Z].*")) {
                suggestions.add("Add uppercase letters for more complexity.");
            }
            if (!password.matches(".*[a-z].*")) {
                suggestions.add("Add lowercase letters for more complexity.");
            }
            if (!password.matches(".*[0-9].*")) {
                suggestions.add("Add numbers for more complexity.");
            }
            if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
                suggestions.add("Add special characters (!@#$%^&*) for maximum security.");
            }

            // Common patterns
            if (password.toLowerCase().contains(username.toLowerCase())) {
                suggestions.add("Don't include your username in the password.");
            }
            if (password.matches(".*(.)\\1{2,}.*")) {
                suggestions.add("Avoid repeated characters (like 'aaa' or '111').");
            }
            if (containsSequence(password)) {
                suggestions.add("Avoid sequential characters (like 'abc' or '123').");
            }
            if (containsKeyboardPattern(password)) {
                suggestions.add("Avoid keyboard patterns (like 'qwerty' or 'asdf').");
            }

            // Common passwords
            if (isCommonPassword(password)) {
                suggestions.add("This is a commonly used password. Choose something unique.");
            }

            return suggestions;
        }

        private boolean containsSequence(String password) {
            String lower = password.toLowerCase();
            for (int i = 0; i < lower.length() - 2; i++) {
                char c1 = lower.charAt(i);
                char c2 = lower.charAt(i + 1);
                char c3 = lower.charAt(i + 2);

                if ((c2 == c1 + 1 && c3 == c2 + 1) ||
                    (c2 == c1 - 1 && c3 == c2 - 1)) {
                    return true;
                }
            }
            return false;
        }

        private boolean containsKeyboardPattern(String password) {
            String[] patterns = {"qwerty", "asdf", "zxcv", "qazwsx", "password", "letmein"};
            String lower = password.toLowerCase();
            for (String pattern : patterns) {
                if (lower.contains(pattern)) {
                    return true;
                }
            }
            return false;
        }

        private boolean isCommonPassword(String password) {
            String[] common = {"password", "123456", "12345678", "qwerty", "abc123",
                             "monkey", "master", "dragon", "111111", "baseball",
                             "iloveyou", "trustno1", "sunshine", "princess", "welcome"};
            String lower = password.toLowerCase();
            for (String c : common) {
                if (lower.equals(c)) {
                    return true;
                }
            }
            return false;
        }
    }
}
