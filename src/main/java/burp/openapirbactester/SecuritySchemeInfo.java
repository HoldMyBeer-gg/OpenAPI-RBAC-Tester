package burp.openapirbactester;

/**
 * Snapshot of a single OpenAPI security scheme declared under
 * {@code components.securitySchemes}. Immutable. Null-valued fields indicate
 * "not applicable for this scheme type" (e.g., {@code apiKeyName} is only
 * populated when {@link #type()} is {@link SchemeType#API_KEY}).
 */
public record SecuritySchemeInfo(
        String name,
        SchemeType type,
        String apiKeyLocation,
        String apiKeyName,
        String bearerFormat
) {

    public enum SchemeType { BEARER, API_KEY, BASIC, OAUTH2, OPEN_ID_CONNECT, OTHER }

    public static SecuritySchemeInfo bearer(String name, String bearerFormat) {
        return new SecuritySchemeInfo(name, SchemeType.BEARER, null, null, bearerFormat);
    }

    public static SecuritySchemeInfo apiKey(String name, String apiKeyLocation, String apiKeyName) {
        return new SecuritySchemeInfo(name, SchemeType.API_KEY, apiKeyLocation, apiKeyName, null);
    }

    public static SecuritySchemeInfo basic(String name) {
        return new SecuritySchemeInfo(name, SchemeType.BASIC, null, null, null);
    }

    public static SecuritySchemeInfo oauth2(String name) {
        return new SecuritySchemeInfo(name, SchemeType.OAUTH2, null, null, null);
    }

    public static SecuritySchemeInfo openIdConnect(String name) {
        return new SecuritySchemeInfo(name, SchemeType.OPEN_ID_CONNECT, null, null, null);
    }

    public static SecuritySchemeInfo other(String name) {
        return new SecuritySchemeInfo(name, SchemeType.OTHER, null, null, null);
    }

    /** Short human-readable description for UI hints (e.g. "X-API-Key (header)"). */
    public String displayName() {
        return switch (type) {
            case BEARER -> "Bearer" + (bearerFormat != null && !bearerFormat.isBlank() ? " (" + bearerFormat + ")" : "");
            case API_KEY -> (apiKeyName != null ? apiKeyName : name) + " (" + apiKeyLocation + ")";
            case BASIC -> "Basic";
            case OAUTH2 -> "OAuth2";
            case OPEN_ID_CONNECT -> "OpenID Connect";
            case OTHER -> name;
        };
    }
}
