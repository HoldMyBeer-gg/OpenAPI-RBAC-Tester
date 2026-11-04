package burp.openapirbactester;

import java.util.Locale;

/**
 * Heuristic detector for endpoints whose side effects would invalidate the RBAC
 * comparison run — chiefly session-destroying ones like {@code /logout}, but also
 * destructive mutations ({@code DELETE}, revocation, deactivation) that shouldn't
 * be fired blind across every configured identity.
 * <p>
 * False positives are cheap (user can override via the warning dialog); false
 * negatives are expensive (you logged yourself out mid-run). So we err toward
 * flagging anything plausibly dangerous.
 */
public final class DestructiveEndpointDetector {

    private DestructiveEndpointDetector() {}

    public static boolean isLikelyDestructive(ApiEndpoint endpoint) {
        if (endpoint == null) return false;
        if ("DELETE".equalsIgnoreCase(endpoint.getMethod())) return true;
        if (pathLooksDestructive(endpoint.getPath())) return true;
        return false;
    }

    /** Short human reason — surfaced in the warning dialog so the user knows why we flagged. */
    public static String reasonFor(ApiEndpoint endpoint) {
        if (endpoint == null) return "";
        if ("DELETE".equalsIgnoreCase(endpoint.getMethod())) return "DELETE method";
        String lower = endpoint.getPath().toLowerCase(Locale.ROOT);
        if (containsSegment(lower, "logout") || containsSegment(lower, "signout") || containsSegment(lower, "sign-out")
                || containsSegment(lower, "log-out")) {
            return "logout endpoint — would invalidate comparison sessions";
        }
        if (containsSegment(lower, "revoke") || containsSegment(lower, "revocation")) {
            return "token revocation — may invalidate credentials mid-run";
        }
        if (containsSegment(lower, "disable") || containsSegment(lower, "deactivate")) {
            return "disables/deactivates resources";
        }
        if (containsSegment(lower, "destroy") || containsSegment(lower, "purge") || containsSegment(lower, "wipe")) {
            return "destroy/purge/wipe endpoint";
        }
        if (containsSegment(lower, "impersonate") || containsSegment(lower, "assume")) {
            return "impersonation — swaps server-side identity context";
        }
        return "";
    }

    static boolean pathLooksDestructive(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        return containsSegment(lower, "logout") || containsSegment(lower, "signout") || containsSegment(lower, "sign-out")
                || containsSegment(lower, "log-out")
                || containsSegment(lower, "revoke") || containsSegment(lower, "revocation")
                || containsSegment(lower, "disable") || containsSegment(lower, "deactivate")
                || containsSegment(lower, "destroy") || containsSegment(lower, "purge") || containsSegment(lower, "wipe")
                || containsSegment(lower, "impersonate") || containsSegment(lower, "assume");
    }

    /**
     * True if {@code needle} appears as a path segment (bounded by {@code /} or end of string)
     * rather than as a substring buried in another word. Prevents matching things like
     * {@code /payloads} via "loa" or {@code /refresh} via "fresh".
     */
    private static boolean containsSegment(String path, String needle) {
        int idx = 0;
        while ((idx = path.indexOf(needle, idx)) >= 0) {
            boolean leftOk = idx == 0 || !isWordChar(path.charAt(idx - 1));
            int end = idx + needle.length();
            boolean rightOk = end == path.length() || !isWordChar(path.charAt(end));
            if (leftOk && rightOk) return true;
            idx = end;
        }
        return false;
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }
}
