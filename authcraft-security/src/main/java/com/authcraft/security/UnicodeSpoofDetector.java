// com/authcraft/security/UnicodeSpoofDetector.java
package com.authcraft.security;

import com.authcraft.core.config.AuthCraftConfig;

import java.text.Normalizer;
import java.util.*;
import java.util.logging.Logger;

/**
 * Detects Unicode spoofing / homoglyph attacks in usernames.
 * E.g. "Аdmin" (Cyrillic А) vs "Admin" (Latin A).
 */
public class UnicodeSpoofDetector {

    private final AuthCraftConfig config;
    private final Logger logger;

    /**
     * Map of visually similar characters (confusables).
     * Maps each character to its canonical ASCII equivalent.
     */
    private static final Map<Character, Character> CONFUSABLES;

    static {
        Map<Character, Character> map = new HashMap<>();

        // Cyrillic → Latin
        map.put('А', 'A'); map.put('а', 'a');
        map.put('В', 'B'); map.put('в', 'b');  // actually looks like 'B'
        map.put('С', 'C'); map.put('с', 'c');
        map.put('Е', 'E'); map.put('е', 'e');
        map.put('Н', 'H'); map.put('н', 'h');
        map.put('К', 'K'); map.put('к', 'k');
        map.put('М', 'M'); map.put('м', 'm');
        map.put('О', 'O'); map.put('о', 'o');
        map.put('Р', 'P'); map.put('р', 'p');
        map.put('Т', 'T'); map.put('т', 't');
        map.put('Х', 'X'); map.put('х', 'x');
        map.put('У', 'Y'); map.put('у', 'y');
        map.put('І', 'I'); map.put('і', 'i'); // Ukrainian
        map.put('Ј', 'J'); map.put('ј', 'j'); // Serbian

        // Greek → Latin
        map.put('Α', 'A'); map.put('α', 'a');
        map.put('Β', 'B'); map.put('β', 'b');
        map.put('Ε', 'E'); map.put('ε', 'e');
        map.put('Η', 'H'); map.put('η', 'h');
        map.put('Ι', 'I'); map.put('ι', 'i');
        map.put('Κ', 'K'); map.put('κ', 'k');
        map.put('Μ', 'M'); map.put('μ', 'm');
        map.put('Ν', 'N'); map.put('ν', 'n');
        map.put('Ο', 'O'); map.put('ο', 'o');
        map.put('Ρ', 'P'); map.put('ρ', 'p');
        map.put('Τ', 'T'); map.put('τ', 't');
        map.put('Χ', 'X'); map.put('χ', 'x');
        map.put('Ζ', 'Z'); map.put('ζ', 'z');

        // Digit → Letter lookalikes
        map.put('0', 'O');
        map.put('1', 'l');
        map.put('3', 'E');
        map.put('5', 'S');
        map.put('8', 'B');

        // Special characters
        map.put('ℓ', 'l');
        map.put('ı', 'i'); // Turkish dotless i
        map.put('ĺ', 'l');
        map.put('ɑ', 'a');
        map.put('ɡ', 'g');
        map.put('ɩ', 'i');
        map.put('ⅰ', 'i');
        map.put('ⅱ', 'i');
        map.put('ℹ', 'i');

        CONFUSABLES = Collections.unmodifiableMap(map);
    }

    public UnicodeSpoofDetector(AuthCraftConfig config, Logger logger) {
        this.config = config;
        this.logger = logger;
    }

    /**
     * Normalize a username by replacing confusable characters.
     */
    public String normalize(String username) {
        // Step 1: Unicode NFKD normalization
        String normalized = Normalizer.normalize(
                username, Normalizer.Form.NFKD
        );

        // Step 2: Replace confusables
        StringBuilder sb = new StringBuilder();
        for (char c : normalized.toCharArray()) {
            Character replacement = CONFUSABLES.get(c);
            sb.append(replacement != null ? replacement : c);
        }

        // Step 3: Remove combining characters
        return sb.toString()
                .replaceAll("[\\p{InCombiningDiacriticalMarks}]", "")
                .toLowerCase();
    }

    /**
     * Check if a username contains mixed scripts (suspicious).
     */
    public boolean containsMixedScripts(String username) {
        Set<Character.UnicodeScript> scripts = new HashSet<>();

        for (char c : username.toCharArray()) {
            Character.UnicodeScript script =
                    Character.UnicodeScript.of(c);
            if (script != Character.UnicodeScript.COMMON
                    && script != Character.UnicodeScript.INHERITED) {
                scripts.add(script);
            }
        }

        return scripts.size() > 1;
    }

    /**
     * Check if two names are visually similar.
     */
    public boolean areSimilar(String name1, String name2) {
        String norm1 = normalize(name1);
        String norm2 = normalize(name2);

        if (norm1.equals(norm2)) return true;

        // Levenshtein distance check
        int distance = levenshteinDistance(norm1, norm2);
        int maxLen = Math.max(norm1.length(), norm2.length());

        if (maxLen == 0) return true;

        double similarity = 1.0 - ((double) distance / maxLen);
        return similarity >= config.getUnicodeSimilarityThreshold();
    }

    /**
     * Full spoof check result.
     */
    public SpoofCheckResult check(String username,
                                  Collection<String> existingNames) {
        if (!config.isUnicodeSpoofingDetection()) {
            return SpoofCheckResult.safe();
        }

        List<String> issues = new ArrayList<>();

        // 1. Check mixed scripts
        if (containsMixedScripts(username)) {
            issues.add("Mixed Unicode scripts detected");
        }

        // 2. Check against existing names
        String normalized = normalize(username);
        for (String existing : existingNames) {
            if (existing.equalsIgnoreCase(username)) continue;
            if (areSimilar(username, existing)) {
                issues.add("Visually similar to existing user: "
                        + existing);
            }
        }

        // 3. Check for non-ASCII in Latin-expected names
        boolean hasNonAscii = username.chars()
                .anyMatch(c -> c > 127);
        boolean looksLatin = username.matches(".*[a-zA-Z].*");
        if (hasNonAscii && looksLatin) {
            issues.add("Contains non-ASCII characters in "
                    + "Latin-like username");
        }

        if (!issues.isEmpty()) {
            return SpoofCheckResult.suspicious(
                    normalized, issues
            );
        }

        return SpoofCheckResult.safe();
    }

    /**
     * Standard Levenshtein distance implementation.
     */
    public static int levenshteinDistance(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();

        int[][] dp = new int[len1 + 1][len2 + 1];

        for (int i = 0; i <= len1; i++) dp[i][0] = i;
        for (int j = 0; j <= len2; j++) dp[0][j] = j;

        for (int i = 1; i <= len1; i++) {
            for (int j = 1; j <= len2; j++) {
                int cost = s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(
                        Math.min(dp[i-1][j] + 1, dp[i][j-1] + 1),
                        dp[i-1][j-1] + cost
                );
            }
        }

        return dp[len1][len2];
    }

    // =============================================
    // Result class
    // =============================================

    public static class SpoofCheckResult {
        private final boolean safe;
        private final String normalizedName;
        private final List<String> issues;

        private SpoofCheckResult(boolean safe,
                                 String normalizedName,
                                 List<String> issues) {
            this.safe = safe;
            this.normalizedName = normalizedName;
            this.issues = issues;
        }

        public static SpoofCheckResult safe() {
            return new SpoofCheckResult(true, null, List.of());
        }

        public static SpoofCheckResult suspicious(
                String normalizedName, List<String> issues) {
            return new SpoofCheckResult(false, normalizedName, issues);
        }

        public boolean isSafe() { return safe; }
        public String getNormalizedName() { return normalizedName; }
        public List<String> getIssues() { return issues; }
    }
}