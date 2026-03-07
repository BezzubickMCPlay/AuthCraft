package com.authcraft.core.service;

import com.authcraft.core.config.AuthCraftConfig;
import com.authcraft.core.exception.WeakPasswordException;

import java.util.*;

public class PasswordValidator {

    private final AuthCraftConfig config;
    private final PasswordBlacklist blacklist;

    private static final String[] SEQUENCES = {
        "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba",
        "01234567890", "09876543210", "qwertyuiop", "asdfghjkl",
        "zxcvbnm", "!@#$%^&*()"
    };

    public PasswordValidator(AuthCraftConfig config, PasswordBlacklist blacklist) {
        this.config = config;
        this.blacklist = blacklist;
    }

    public void validate(String password, String username) {
        List<String> violations = new ArrayList<>();

        if (password.length() < config.getPasswordMinLength())
            violations.add("Minimum " + config.getPasswordMinLength() + " characters");
        if (password.length() > config.getPasswordMaxLength())
            violations.add("Maximum " + config.getPasswordMaxLength() + " characters");
        if (config.isPasswordRequireUppercase() && password.chars().noneMatch(Character::isUpperCase))
            violations.add("Must contain uppercase letter");
        if (config.isPasswordRequireLowercase() && password.chars().noneMatch(Character::isLowerCase))
            violations.add("Must contain lowercase letter");
        if (config.isPasswordRequireDigit() && password.chars().noneMatch(Character::isDigit))
            violations.add("Must contain digit");
        if (config.isPasswordRequireSpecial() && password.chars().noneMatch(c -> !Character.isLetterOrDigit(c)))
            violations.add("Must contain special character");

        if (config.isPasswordCheckUsername() && username != null && username.length() >= 3) {
            String lp = password.toLowerCase(), lu = username.toLowerCase();
            if (lp.contains(lu)) violations.add("Must not contain username");
            if (lp.contains(new StringBuilder(lu).reverse().toString()))
                violations.add("Must not contain reversed username");
        }

        if (config.isPasswordCheckBlacklist() && blacklist.isBlacklisted(password))
            violations.add("Password is too common");

        if (config.isPasswordCheckSequences()) {
            if (containsSequence(password, 4)) violations.add("Contains common sequence");
            if (containsRepeats(password, 3)) violations.add("Contains repeating characters");
        }

        int score = calculateEntropyScore(password);
        if (score < config.getPasswordMinScore())
            violations.add("Too weak (score: " + score + "/" + config.getPasswordMinScore() + ")");

        if (!violations.isEmpty()) throw new WeakPasswordException(violations);
    }

    /**
     * Get detailed password strength analysis for real-time feedback.
     * @param password The password to analyze
     * @param username The username (for checking if password contains it)
     * @return PasswordStrength object with score, level, and requirement status
     */
    public PasswordStrength analyzeStrength(String password, String username) {
        if (password == null || password.isEmpty()) {
            return new PasswordStrength(0, StrengthLevel.VERY_WEAK, new ArrayList<>(), new ArrayList<>());
        }

        List<RequirementResult> requirements = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // Check length
        boolean lengthOk = password.length() >= config.getPasswordMinLength()
            && password.length() <= config.getPasswordMaxLength();
        requirements.add(new RequirementResult("length", lengthOk,
            password.length() + "/" + config.getPasswordMinLength() + "-" + config.getPasswordMaxLength()));

        // Check uppercase
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        if (config.isPasswordRequireUppercase()) {
            requirements.add(new RequirementResult("uppercase", hasUpper, hasUpper ? "✓" : "✗"));
        }

        // Check lowercase
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        if (config.isPasswordRequireLowercase()) {
            requirements.add(new RequirementResult("lowercase", hasLower, hasLower ? "✓" : "✗"));
        }

        // Check digit
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        if (config.isPasswordRequireDigit()) {
            requirements.add(new RequirementResult("digit", hasDigit, hasDigit ? "✓" : "✗"));
        }

        // Check special character
        boolean hasSpecial = password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));
        if (config.isPasswordRequireSpecial()) {
            requirements.add(new RequirementResult("special", hasSpecial, hasSpecial ? "✓" : "✗"));
        }

        // Check username containment
        if (config.isPasswordCheckUsername() && username != null && username.length() >= 3) {
            String lp = password.toLowerCase(), lu = username.toLowerCase();
            boolean containsUsername = lp.contains(lu) || lp.contains(new StringBuilder(lu).reverse().toString());
            if (containsUsername) {
                warnings.add("Contains username");
            }
        }

        // Check blacklist
        if (config.isPasswordCheckBlacklist() && blacklist.isBlacklisted(password)) {
            warnings.add("Password is too common");
        }

        // Check sequences
        if (config.isPasswordCheckSequences()) {
            if (containsSequence(password, 4)) warnings.add("Contains common sequence");
            if (containsRepeats(password, 3)) warnings.add("Contains repeating characters");
        }

        int score = calculateEntropyScore(password);
        StrengthLevel level = determineLevel(score);

        return new PasswordStrength(score, level, requirements, warnings);
    }

    /**
     * Get progressive requirements display - shows what's needed next to improve password.
     * @param password Current password input
     * @param username Username for validation
     * @return List of suggestions to improve the password
     */
    public List<String> getProgressiveSuggestions(String password, String username) {
        List<String> suggestions = new ArrayList<>();
        
        if (password == null || password.isEmpty()) {
            suggestions.add("Enter a password");
            return suggestions;
        }

        // Length suggestions
        if (password.length() < config.getPasswordMinLength()) {
            suggestions.add("Add " + (config.getPasswordMinLength() - password.length()) + " more characters");
        }

        // Character type suggestions
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));

        if (config.isPasswordRequireUppercase() && !hasUpper) {
            suggestions.add("Add an uppercase letter (A-Z)");
        }
        if (config.isPasswordRequireLowercase() && !hasLower) {
            suggestions.add("Add a lowercase letter (a-z)");
        }
        if (config.isPasswordRequireDigit() && !hasDigit) {
            suggestions.add("Add a number (0-9)");
        }
        if (config.isPasswordRequireSpecial() && !hasSpecial) {
            suggestions.add("Add a special character (!@#$%^&*)");
        }

        // Username check
        if (config.isPasswordCheckUsername() && username != null && username.length() >= 3) {
            String lp = password.toLowerCase(), lu = username.toLowerCase();
            if (lp.contains(lu) || lp.contains(new StringBuilder(lu).reverse().toString())) {
                suggestions.add("Remove your username from the password");
            }
        }

        // Entropy improvement
        int score = calculateEntropyScore(password);
        if (score < config.getPasswordMinScore()) {
            suggestions.add("Make it more unique (add variety)");
        }

        // Sequence warnings
        if (config.isPasswordCheckSequences()) {
            if (containsSequence(password, 4)) {
                suggestions.add("Avoid common sequences (like 1234, qwerty)");
            }
            if (containsRepeats(password, 3)) {
                suggestions.add("Avoid repeating characters (like aaa)");
            }
        }

        return suggestions;
    }

    private StrengthLevel determineLevel(int score) {
        if (score < 20) return StrengthLevel.VERY_WEAK;
        if (score < 40) return StrengthLevel.WEAK;
        if (score < 60) return StrengthLevel.FAIR;
        if (score < 80) return StrengthLevel.STRONG;
        return StrengthLevel.VERY_STRONG;
    }

    public int calculateEntropyScore(String password) {
        if (password == null || password.isEmpty()) return 0;
        double score = 0;
        int length = password.length();
        score += Math.min(30, length * 2.5);

        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
        Set<Character> unique = new HashSet<>();
        for (char c : password.toCharArray()) {
            unique.add(c);
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        int charsetSize = 0;
        if (hasLower) { charsetSize += 26; score += 5; }
        if (hasUpper) { charsetSize += 26; score += 8; }
        if (hasDigit) { charsetSize += 10; score += 5; }
        if (hasSpecial) { charsetSize += 32; score += 12; }

        score += ((double) unique.size() / length) * 15;
        if (charsetSize > 0) score += Math.min(15, (Math.log(charsetSize) / Math.log(2)) * length / 5);
        if (containsSequence(password, 3)) score -= 10;
        if (containsRepeats(password, 3)) score -= 10;

        return (int) Math.max(0, Math.min(100, score));
    }

    private boolean containsSequence(String password, int minLen) {
        String lower = password.toLowerCase();
        for (String seq : SEQUENCES)
            for (int i = 0; i <= seq.length() - minLen; i++)
                if (lower.contains(seq.substring(i, i + minLen))) return true;
        return false;
    }

    private boolean containsRepeats(String password, int minRepeat) {
        for (int i = 0; i <= password.length() - minRepeat; i++) {
            char c = password.charAt(i);
            boolean all = true;
            for (int j = 1; j < minRepeat; j++)
                if (password.charAt(i + j) != c) { all = false; break; }
            if (all) return true;
        }
        return false;
    }

    /**
     * Enum representing password strength levels.
     */
    public enum StrengthLevel {
        VERY_WEAK("Very Weak", "§c", 0),
        WEAK("Weak", "§c", 1),
        FAIR("Fair", "§e", 2),
        STRONG("Strong", "§a", 3),
        VERY_STRONG("Very Strong", "§2", 4);

        private final String label;
        private final String color;
        private final int level;

        StrengthLevel(String label, String color, int level) {
            this.label = label;
            this.color = color;
            this.level = level;
        }

        public String getLabel() { return label; }
        public String getColor() { return color; }
        public int getLevel() { return level; }
    }

    /**
     * Represents a single password requirement check result.
     */
    public static class RequirementResult {
        private final String name;
        private final boolean passed;
        private final String display;

        public RequirementResult(String name, boolean passed, String display) {
            this.name = name;
            this.passed = passed;
            this.display = display;
        }

        public String getName() { return name; }
        public boolean isPassed() { return passed; }
        public String getDisplay() { return display; }
    }

    /**
     * Complete password strength analysis result.
     */
    public static class PasswordStrength {
        private final int score;
        private final StrengthLevel level;
        private final List<RequirementResult> requirements;
        private final List<String> warnings;

        public PasswordStrength(int score, StrengthLevel level,
                List<RequirementResult> requirements, List<String> warnings) {
            this.score = score;
            this.level = level;
            this.requirements = requirements;
            this.warnings = warnings;
        }

        public int getScore() { return score; }
        public StrengthLevel getLevel() { return level; }
        public List<RequirementResult> getRequirements() { return requirements; }
        public List<String> getWarnings() { return warnings; }
        
        public boolean isAcceptable() {
            return requirements.stream().allMatch(RequirementResult::isPassed)
                && warnings.isEmpty()
                && score >= 40;
        }

        /**
         * Get a progress bar representation of the password strength.
         * @param length The length of the progress bar (default 10)
         * @return A colored progress bar string
         */
        public String getProgressBar(int length) {
            int filled = (int) Math.ceil((score / 100.0) * length);
            StringBuilder bar = new StringBuilder(level.getColor());
            for (int i = 0; i < length; i++) {
                bar.append(i < filled ? "█" : "░");
            }
            bar.append("§r");
            return bar.toString();
        }
    }
}