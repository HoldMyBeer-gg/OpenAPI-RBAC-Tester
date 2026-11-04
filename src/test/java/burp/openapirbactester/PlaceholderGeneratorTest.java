package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PlaceholderGeneratorTest {

    @Test
    void exampleAlwaysWins() {
        assertEquals("custom-id",
                PlaceholderGenerator.placeholderFor("string", "uuid", "custom-id"));
        assertEquals("custom-id",
                PlaceholderGenerator.placeholderFor(null, null, "custom-id"));
    }

    @Test
    void exampleBlankDoesNotWin() {
        assertEquals("00000000-0000-0000-0000-000000000001",
                PlaceholderGenerator.placeholderFor("string", "uuid", ""));
        assertEquals("00000000-0000-0000-0000-000000000001",
                PlaceholderGenerator.placeholderFor("string", "uuid", "   "));
    }

    @Test
    void integerAndNumber() {
        assertEquals("1", PlaceholderGenerator.placeholderFor("integer", null, null));
        assertEquals("1", PlaceholderGenerator.placeholderFor("number", null, null));
    }

    @Test
    void booleanPlaceholder() {
        assertEquals("true", PlaceholderGenerator.placeholderFor("boolean", null, null));
    }

    @Test
    void stringWithUuid() {
        assertEquals("00000000-0000-0000-0000-000000000001",
                PlaceholderGenerator.placeholderFor("string", "uuid", null));
    }

    @Test
    void stringWithDateTimeAndDate() {
        assertEquals("2026-01-01T00:00:00Z",
                PlaceholderGenerator.placeholderFor("string", "date-time", null));
        assertEquals("2026-01-01",
                PlaceholderGenerator.placeholderFor("string", "date", null));
        assertEquals("00:00:00",
                PlaceholderGenerator.placeholderFor("string", "time", null));
    }

    @Test
    void stringWithEmailVariants() {
        assertEquals("test@example.com",
                PlaceholderGenerator.placeholderFor("string", "email", null));
        assertEquals("test@example.com",
                PlaceholderGenerator.placeholderFor("string", "idn-email", null));
    }

    @Test
    void stringWithHostnameAndIdnHostname() {
        assertEquals("example.com",
                PlaceholderGenerator.placeholderFor("string", "hostname", null));
        assertEquals("example.com",
                PlaceholderGenerator.placeholderFor("string", "idn-hostname", null));
    }

    @Test
    void stringWithIpAddresses() {
        assertEquals("127.0.0.1",
                PlaceholderGenerator.placeholderFor("string", "ipv4", null));
        assertEquals("::1",
                PlaceholderGenerator.placeholderFor("string", "ipv6", null));
    }

    @Test
    void stringWithUriVariants() {
        assertEquals("https://example.com",
                PlaceholderGenerator.placeholderFor("string", "uri", null));
        assertEquals("https://example.com",
                PlaceholderGenerator.placeholderFor("string", "url", null));
        assertEquals("https://example.com",
                PlaceholderGenerator.placeholderFor("string", "iri", null));
        assertEquals("https://example.com",
                PlaceholderGenerator.placeholderFor("string", "uri-reference", null));
    }

    @Test
    void stringWithByteAndBinary() {
        assertEquals("dGVzdA==",
                PlaceholderGenerator.placeholderFor("string", "byte", null));
        assertEquals("test",
                PlaceholderGenerator.placeholderFor("string", "binary", null));
    }

    @Test
    void stringWithPasswordAndRegex() {
        assertEquals("password",
                PlaceholderGenerator.placeholderFor("string", "password", null));
        assertEquals(".*",
                PlaceholderGenerator.placeholderFor("string", "regex", null));
    }

    @Test
    void stringWithoutFormat_usesDefault() {
        assertEquals("1", PlaceholderGenerator.placeholderFor("string", null, null));
        assertEquals("1", PlaceholderGenerator.placeholderFor("string", "", null));
    }

    @Test
    void unknownTypeAndFormat_usesDefault() {
        assertEquals("1", PlaceholderGenerator.placeholderFor(null, null, null));
        assertEquals("1", PlaceholderGenerator.placeholderFor("", "", null));
        assertEquals("1", PlaceholderGenerator.placeholderFor("nonsense", "also-nonsense", null));
    }

    @Test
    void stringWithUriTemplate() {
        assertEquals("/example/{id}",
                PlaceholderGenerator.placeholderFor("string", "uri-template", null));
    }

    @Test
    void caseInsensitive() {
        assertEquals("00000000-0000-0000-0000-000000000001",
                PlaceholderGenerator.placeholderFor("STRING", "UUID", null));
        assertEquals("true",
                PlaceholderGenerator.placeholderFor("BOOLEAN", null, null));
    }

    @Test
    void exampleTrimmed() {
        assertEquals("abc-123",
                PlaceholderGenerator.placeholderFor("string", "uuid", "  abc-123  "));
    }
}
