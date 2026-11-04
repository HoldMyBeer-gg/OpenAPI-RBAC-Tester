package burp.openapirbactester;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Classifies HTTP request headers for "import from request" flow — separates auth-bearing
 * headers from browser/transport noise, decodes Basic, and detects OpenAPI spec sources.
 */
public final class HeaderClassifier {

    /** Browser/transport headers that should not be copied onto generated API requests. */
    private static final Set<String> DENYLIST_LOWER = Set.of(
            "host", "user-agent",
            "accept", "accept-encoding", "accept-language", "accept-charset",
            "connection", "content-type", "content-length", "transfer-encoding",
            "referer", "origin",
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-arch",
            "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-model",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
            "upgrade-insecure-requests", "priority", "dnt",
            "cache-control", "pragma",
            "if-modified-since", "if-none-match", "if-match", "if-unmodified-since",
            "te", "expect", "max-forwards",
            "x-pwnfox-color"
    );

    public record Extracted(
            String bearerToken,
            String basicUser,
            String basicPass,
            String apiKeyName,
            String apiKeyValue,
            List<AuthConfig.HeaderPair> extraHeaders
    ) {}

    private HeaderClassifier() {}

    /**
     * Classifies raw header lines (as they appear on the wire, excluding the request-line).
     * Accepts a list of {@code "Name: Value"} strings. Returns auth candidates separated
     * from the extras list.
     */
    public static Extracted fromRawHeaderLines(List<String> headerLines) {
        String bearer = null;
        String basicUser = null;
        String basicPass = null;
        String apiKeyName = null;
        String apiKeyValue = null;
        List<AuthConfig.HeaderPair> extras = new ArrayList<>();

        for (String line : headerLines) {
            if (line == null) continue;
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).replaceFirst("^ ", "");
            if (name.isEmpty()) continue;
            String lower = name.toLowerCase(Locale.ROOT);

            if ("authorization".equals(lower)) {
                if (startsWithIgnoreCase(value, "Bearer ")) {
                    bearer = value.substring(7).trim();
                    continue;
                }
                if (startsWithIgnoreCase(value, "Basic ")) {
                    String decoded = decodeBasic(value.substring(6).trim());
                    if (decoded != null) {
                        int sep = decoded.indexOf(':');
                        if (sep >= 0) {
                            basicUser = decoded.substring(0, sep);
                            basicPass = decoded.substring(sep + 1);
                            continue;
                        }
                    }
                }
                extras.add(new AuthConfig.HeaderPair(name, value));
                continue;
            }

            if ("x-api-key".equals(lower) && apiKeyValue == null) {
                apiKeyName = name;
                apiKeyValue = value;
                continue;
            }

            if (DENYLIST_LOWER.contains(lower)) continue;
            extras.add(new AuthConfig.HeaderPair(name, value));
        }

        return new Extracted(bearer, basicUser, basicPass, apiKeyName, apiKeyValue,
                Collections.unmodifiableList(extras));
    }

    /** True if the URL path looks like a common OpenAPI/Swagger spec endpoint. */
    public static boolean isSpecUrlPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        int query = lower.indexOf('?');
        if (query >= 0) lower = lower.substring(0, query);
        return lower.endsWith("/openapi.json") || lower.endsWith("/openapi.yaml") || lower.endsWith("/openapi.yml")
                || lower.endsWith("/swagger.json") || lower.endsWith("/swagger.yaml") || lower.endsWith("/swagger.yml")
                || lower.endsWith("/api-docs") || lower.endsWith("/v2/api-docs") || lower.endsWith("/v3/api-docs")
                || lower.endsWith("/docs/openapi.json");
    }

    /** True if the response body looks like an OpenAPI spec (JSON or YAML). */
    public static boolean looksLikeSpecBody(String body) {
        if (body == null || body.isBlank()) return false;
        String trimmed = body.trim();
        if (trimmed.startsWith("{")) {
            String peek = trimmed.substring(0, Math.min(2048, trimmed.length())).toLowerCase(Locale.ROOT);
            return peek.contains("\"openapi\"") || peek.contains("\"swagger\"");
        }
        String firstLine = trimmed.split("\\r?\\n", 2)[0].trim().toLowerCase(Locale.ROOT);
        return firstLine.startsWith("openapi:") || firstLine.startsWith("swagger:");
    }

    private static boolean startsWithIgnoreCase(String s, String prefix) {
        return s != null && s.length() >= prefix.length()
                && s.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    private static String decodeBasic(String b64) {
        try {
            return new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
