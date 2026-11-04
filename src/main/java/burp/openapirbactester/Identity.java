package burp.openapirbactester;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A named auth configuration, for multi-identity RBAC testing.
 * <p>
 * Carries an {@link AuthConfig} plus a base-URL override so switching identities
 * also switches the target host when testing against different environments per
 * role (e.g., admin on staging, user on prod). Serialises to a single URL-encoded
 * key-value string for persistence across Burp restarts.
 */
public final class Identity {

    private final String name;
    private final AuthConfig authConfig;
    private final String baseUrlOverride;

    public Identity(String name, AuthConfig authConfig, String baseUrlOverride) {
        this.name = Objects.requireNonNull(name, "name").trim();
        if (this.name.isEmpty()) throw new IllegalArgumentException("Identity name must not be blank");
        this.authConfig = authConfig != null ? authConfig : AuthConfig.empty();
        this.baseUrlOverride = baseUrlOverride != null ? baseUrlOverride : "";
    }

    public static Identity empty(String name) {
        return new Identity(name, AuthConfig.empty(), "");
    }

    public String name() { return name; }
    public AuthConfig authConfig() { return authConfig; }
    public String baseUrlOverride() { return baseUrlOverride; }

    public Identity withName(String newName) {
        return new Identity(newName, authConfig, baseUrlOverride);
    }

    /**
     * Serialises this identity to a single URL-encoded string: {@code k1=v1&k2=v2&...}.
     * All keys and values are URL-encoded so delimiters can't collide with content.
     * The extra-headers block is serialised as its raw multi-line text (inside encoding).
     */
    public String serialise() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("name", name);
        fields.put("bearer", authConfig.bearerToken());
        fields.put("apiKeyValue", authConfig.apiKeyValue());
        fields.put("apiKeyName", authConfig.apiKeyName());
        fields.put("apiKeyLocation", authConfig.apiKeyLocation().name());
        fields.put("basicUser", authConfig.basicUser());
        fields.put("basicPass", authConfig.basicPass());
        fields.put("extraHeadersRaw", serialiseExtraHeaders(authConfig.extraHeaders()));
        fields.put("baseUrlOverride", baseUrlOverride);

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(encode(e.getKey())).append('=').append(encode(e.getValue()));
        }
        return sb.toString();
    }

    /**
     * Reconstructs an identity from {@link #serialise()}. Unknown keys are ignored;
     * missing keys default to empty strings. Throws only if the name is missing or
     * blank after decoding (a nameless identity is always a data-integrity error).
     */
    public static Identity deserialise(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            throw new IllegalArgumentException("Cannot deserialise empty string");
        }
        Map<String, String> fields = new LinkedHashMap<>();
        for (String pair : encoded.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            String k = decode(pair.substring(0, eq));
            String v = decode(pair.substring(eq + 1));
            fields.put(k, v);
        }
        String name = fields.getOrDefault("name", "");
        if (name.isBlank()) throw new IllegalArgumentException("Missing or blank identity name in encoded payload");

        AuthConfig.ApiKeyLocation loc;
        try {
            loc = AuthConfig.ApiKeyLocation.valueOf(fields.getOrDefault("apiKeyLocation", "HEADER"));
        } catch (IllegalArgumentException e) {
            loc = AuthConfig.ApiKeyLocation.HEADER;
        }

        List<AuthConfig.HeaderPair> extras = AuthConfig.parseExtraHeaders(fields.getOrDefault("extraHeadersRaw", ""));

        AuthConfig auth = new AuthConfig(
                fields.getOrDefault("bearer", ""),
                fields.getOrDefault("apiKeyValue", ""),
                fields.getOrDefault("apiKeyName", ""),
                loc,
                fields.getOrDefault("basicUser", ""),
                fields.getOrDefault("basicPass", ""),
                extras
        );
        return new Identity(name, auth, fields.getOrDefault("baseUrlOverride", ""));
    }

    private static String serialiseExtraHeaders(List<AuthConfig.HeaderPair> headers) {
        if (headers == null || headers.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (AuthConfig.HeaderPair h : headers) {
            if (sb.length() > 0) sb.append('\n');
            sb.append(h.name()).append(": ").append(h.value());
        }
        return sb.toString();
    }

    private static String encode(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Identity that)) return false;
        return name.equals(that.name)
                && authConfigEquals(authConfig, that.authConfig)
                && baseUrlOverride.equals(that.baseUrlOverride);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, authConfig.bearerToken(), authConfig.apiKeyValue(),
                authConfig.apiKeyName(), authConfig.apiKeyLocation(),
                authConfig.basicUser(), authConfig.basicPass(),
                serialiseExtraHeaders(new ArrayList<>(authConfig.extraHeaders())),
                baseUrlOverride);
    }

    /** AuthConfig doesn't override equals; compare field-by-field. */
    private static boolean authConfigEquals(AuthConfig a, AuthConfig b) {
        if (a == null || b == null) return a == b;
        return a.bearerToken().equals(b.bearerToken())
                && a.apiKeyValue().equals(b.apiKeyValue())
                && a.apiKeyName().equals(b.apiKeyName())
                && a.apiKeyLocation() == b.apiKeyLocation()
                && a.basicUser().equals(b.basicUser())
                && a.basicPass().equals(b.basicPass())
                && serialiseExtraHeaders(new ArrayList<>(a.extraHeaders()))
                   .equals(serialiseExtraHeaders(new ArrayList<>(b.extraHeaders())));
    }
}
