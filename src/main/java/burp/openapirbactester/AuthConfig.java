package burp.openapirbactester;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Immutable auth credentials applied to every generated request. Supports bearer
 * tokens, API keys (header/query/cookie), HTTP Basic, and arbitrary extra
 * headers. An empty instance adds no auth.
 */
public final class AuthConfig {

    public enum ApiKeyLocation { HEADER, QUERY, COOKIE }

    public record HeaderPair(String name, String value) {}

    private final String bearerToken;
    private final String apiKeyValue;
    private final String apiKeyName;
    private final ApiKeyLocation apiKeyLocation;
    private final String basicUser;
    private final String basicPass;
    private final List<HeaderPair> extraHeaders;

    public AuthConfig(String bearerToken,
                      String apiKeyValue, String apiKeyName, ApiKeyLocation apiKeyLocation,
                      String basicUser, String basicPass) {
        this(bearerToken, apiKeyValue, apiKeyName, apiKeyLocation, basicUser, basicPass, null);
    }

    public AuthConfig(String bearerToken,
                      String apiKeyValue, String apiKeyName, ApiKeyLocation apiKeyLocation,
                      String basicUser, String basicPass,
                      List<HeaderPair> extraHeaders) {
        this.bearerToken = stripWhitespace(bearerToken);
        this.apiKeyValue = trim(apiKeyValue);
        this.apiKeyName = trim(apiKeyName);
        this.apiKeyLocation = apiKeyLocation != null ? apiKeyLocation : ApiKeyLocation.HEADER;
        this.basicUser = trim(basicUser);
        this.basicPass = basicPass != null ? basicPass : "";
        this.extraHeaders = extraHeaders != null
                ? Collections.unmodifiableList(new ArrayList<>(extraHeaders))
                : Collections.emptyList();
    }

    public static AuthConfig empty() {
        return new AuthConfig(null, null, null, null, null, null, null);
    }

    /**
     * Parses a block of raw header lines (one per line, {@code Name: Value}) into
     * a list of header pairs. Blank lines and lines without a colon are dropped.
     */
    public static List<HeaderPair> parseExtraHeaders(String rawText) {
        if (rawText == null || rawText.isBlank()) return Collections.emptyList();
        List<HeaderPair> result = new ArrayList<>();
        for (String line : rawText.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            int idx = trimmed.indexOf(':');
            if (idx <= 0) continue;
            String name = trimmed.substring(0, idx).trim();
            String value = trimmed.substring(idx + 1).replaceFirst("^ ", "");
            if (name.isEmpty()) continue;
            result.add(new HeaderPair(name, value));
        }
        return Collections.unmodifiableList(result);
    }

    public boolean hasBearer() {
        return !bearerToken.isEmpty();
    }

    public boolean hasApiKey() {
        return !apiKeyValue.isEmpty() && !apiKeyName.isEmpty();
    }

    public boolean hasBasic() {
        return !basicUser.isEmpty();
    }

    public boolean isEmpty() {
        return !hasBearer() && !hasApiKey() && !hasBasic() && extraHeaders.isEmpty();
    }

    /**
     * Whether this config carries something that identifies a principal: bearer, API key,
     * basic auth, or an extra header that looks like one (Cookie, Authorization, anything
     * with token/session/key/auth in its name). Unlike {@link #isEmpty()}, a config holding
     * only browser noise such as X-Requested-With does not count. Used by the RBAC grid to
     * tell "anonymous" from "logged in" without trusting the identity's name.
     */
    public boolean hasCredentials() {
        if (hasBearer() || hasApiKey() || hasBasic()) return true;
        for (HeaderPair h : extraHeaders) {
            if (looksLikeCredentialHeader(h.name())) return true;
        }
        return false;
    }

    private static boolean looksLikeCredentialHeader(String name) {
        String n = name == null ? "" : name.toLowerCase(java.util.Locale.ROOT);
        if (n.equals("cookie") || n.equals("authorization") || n.equals("proxy-authorization")) return true;
        return n.contains("token") || n.contains("session") || n.contains("auth")
                || n.contains("key") || n.contains("jwt") || n.contains("secret");
    }

    public String bearerToken() { return bearerToken; }
    public String apiKeyValue() { return apiKeyValue; }
    public String apiKeyName() { return apiKeyName; }
    public ApiKeyLocation apiKeyLocation() { return apiKeyLocation; }
    public String basicUser() { return basicUser; }
    public String basicPass() { return basicPass; }
    public List<HeaderPair> extraHeaders() { return extraHeaders; }

    public String basicAuthorizationHeaderValue() {
        String raw = basicUser + ":" + basicPass;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    private static String stripWhitespace(String s) {
        return s == null ? "" : s.replaceAll("\\s+", "");
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }
}
