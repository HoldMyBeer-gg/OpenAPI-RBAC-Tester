package burp.openapirbactester;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A single expectation: "endpoints matching {@link #tagPattern} should only be
 * accessible to identities matching one of {@link #allowedIdentityPatterns}."
 * Both the tag and identity patterns use shell-style globs: {@code *} matches any
 * run of characters, {@code ?} matches a single character, everything else is
 * literal. Case-insensitive throughout.
 */
public record AccessRule(String tagPattern, List<String> allowedIdentityPatterns) {

    public AccessRule {
        if (tagPattern == null || tagPattern.isBlank()) {
            throw new IllegalArgumentException("tagPattern must not be blank");
        }
        if (allowedIdentityPatterns == null || allowedIdentityPatterns.isEmpty()) {
            throw new IllegalArgumentException("allowedIdentityPatterns must not be empty");
        }
        allowedIdentityPatterns = List.copyOf(allowedIdentityPatterns);
    }

    /** True if any of the endpoint's tags match this rule's tag pattern. */
    public boolean appliesTo(List<String> tags) {
        if (tags == null || tags.isEmpty()) return matchesGlob(tagPattern, "");
        Pattern p = globToRegex(tagPattern);
        for (String t : tags) {
            if (t != null && p.matcher(t).matches()) return true;
        }
        return false;
    }

    /** True if the given identity name matches any of the allowed identity patterns. */
    public boolean allows(String identityName) {
        if (identityName == null) identityName = "";
        for (String pattern : allowedIdentityPatterns) {
            if (matchesGlob(pattern, identityName)) return true;
        }
        return false;
    }

    /**
     * Parses one rule line of the form {@code tagPattern -> allowed1,allowed2,allowed3}.
     * Whitespace around tokens is trimmed. The rule-list separator {@code ,} is the only
     * supported split; commas in patterns are not escapable.
     *
     * @return the parsed rule, or {@code null} if the line is blank, a comment ({@code #...}),
     *         or doesn't contain an arrow.
     */
    public static AccessRule parseLine(String raw) {
        if (raw == null) return null;
        String line = raw.trim();
        if (line.isEmpty() || line.startsWith("#")) return null;
        int arrow = line.indexOf("->");
        if (arrow < 0) return null;
        String tag = line.substring(0, arrow).trim();
        String allowedRaw = line.substring(arrow + 2).trim();
        if (tag.isEmpty() || allowedRaw.isEmpty()) return null;
        if (tag.startsWith("tag:")) tag = tag.substring(4).trim();
        List<String> allowed = new ArrayList<>();
        for (String part : allowedRaw.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) allowed.add(trimmed);
        }
        if (tag.isEmpty() || allowed.isEmpty()) return null;
        return new AccessRule(tag, allowed);
    }

    static boolean matchesGlob(String pattern, String input) {
        return globToRegex(pattern).matcher(input == null ? "" : input).matches();
    }

    static Pattern globToRegex(String glob) {
        StringBuilder regex = new StringBuilder("(?i)^");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*': regex.append(".*"); break;
                case '?': regex.append('.'); break;
                case '.': case '(': case ')': case '+': case '|':
                case '^': case '$': case '@': case '%': case '{': case '}':
                case '[': case ']': case '\\':
                    regex.append("\\").append(c); break;
                default: regex.append(c);
            }
        }
        regex.append('$');
        return Pattern.compile(regex.toString());
    }
}
