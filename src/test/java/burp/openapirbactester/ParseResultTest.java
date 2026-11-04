package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OpenAPIParser.ParseResult}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class ParseResultTest {

    @Test
    void parseResult_getters() {
        var endpoints = List.of(new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/", List.of(), ""));
        var messages = List.of("warning");
        var result = new OpenAPIParser.ParseResult(endpoints, messages, "https://api.test.com");
        assertEquals(endpoints, result.getEndpoints());
        assertEquals(messages, result.getMessages());
        assertEquals("https://api.test.com", result.getDefaultServer());
        assertTrue(result.getSecuritySchemes().isEmpty(),
                "legacy 3-arg constructor should default securitySchemes to empty");
    }

    @Test
    void parseResult_withSecuritySchemes() {
        var endpoints = List.<ApiEndpoint>of();
        var schemes = List.of(SecuritySchemeInfo.bearer("bearerAuth", "JWT"));
        var result = new OpenAPIParser.ParseResult(endpoints, List.of(), "", schemes);
        assertEquals(1, result.getSecuritySchemes().size());
        assertEquals("bearerAuth", result.getSecuritySchemes().get(0).name());
    }

    @Test
    void parseResult_securitySchemesUnmodifiable() {
        var schemes = List.of(SecuritySchemeInfo.bearer("x", null));
        var result = new OpenAPIParser.ParseResult(List.of(), List.of(), "", schemes);
        assertThrows(UnsupportedOperationException.class,
                () -> result.getSecuritySchemes().add(SecuritySchemeInfo.basic("y")));
    }

    @Test
    void parseResult_nullSecuritySchemesTreatedAsEmpty() {
        var result = new OpenAPIParser.ParseResult(List.of(), List.of(), "", null);
        assertTrue(result.getSecuritySchemes().isEmpty());
    }
}
