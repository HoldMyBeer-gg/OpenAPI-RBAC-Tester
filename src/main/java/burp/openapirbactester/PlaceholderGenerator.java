package burp.openapirbactester;

import java.util.Locale;

/**
 * Chooses a syntactically-valid placeholder value for a path parameter based on its
 * OpenAPI schema type/format. The goal is to get past server-side validation so the
 * request reaches the authorisation layer — otherwise strict validators reject
 * {@code /reports/1} with 400 or 404 before any RBAC check runs, and the comparison
 * grid can't distinguish "bad input" from "access denied".
 * <p>
 * Pure data — no Montoya dependency — so this class is trivially unit-testable.
 */
public final class PlaceholderGenerator {

    /** Fallback when no type/format is known or the format isn't recognised. */
    public static final String DEFAULT = "1";

    private PlaceholderGenerator() {}

    /**
     * @param type   OpenAPI schema {@code type} ("integer", "number", "boolean", "string"),
     *               or {@code null}/empty to fall through to default.
     * @param format OpenAPI schema {@code format} ("uuid", "date-time", "email", "ipv4", …),
     *               or {@code null}/empty to apply type-only defaults.
     * @param example Any value found in the schema's {@code example} field, or {@code null}.
     *                When non-null and non-empty this wins — the spec told us what to use.
     */
    public static String placeholderFor(String type, String format, String example) {
        if (example != null && !example.isBlank()) return example.trim();

        String normType = type == null ? "" : type.toLowerCase(Locale.ROOT);
        String normFormat = format == null ? "" : format.toLowerCase(Locale.ROOT);

        return switch (normType) {
            case "integer" -> "1";
            case "number" -> "1";
            case "boolean" -> "true";
            case "string" -> stringPlaceholder(normFormat);
            default -> stringPlaceholder(normFormat);
        };
    }

    private static String stringPlaceholder(String format) {
        return switch (format) {
            case "uuid" -> "00000000-0000-0000-0000-000000000001";
            case "date" -> "2026-01-01";
            case "date-time" -> "2026-01-01T00:00:00Z";
            case "time" -> "00:00:00";
            case "email" -> "test@example.com";
            case "idn-email" -> "test@example.com";
            case "hostname", "idn-hostname" -> "example.com";
            case "ipv4" -> "127.0.0.1";
            case "ipv6" -> "::1";
            case "uri", "url", "iri", "uri-reference" -> "https://example.com";
            case "uri-template" -> "/example/{id}";
            case "byte" -> "dGVzdA==";      // base64("test")
            case "binary" -> "test";
            case "password" -> "password";
            case "regex" -> ".*";
            default -> DEFAULT;
        };
    }
}
