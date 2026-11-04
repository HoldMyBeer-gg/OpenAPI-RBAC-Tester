package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ApiEndpoint} and {@link ApiEndpoint.ParameterInfo}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class ApiEndpointTest {

    @Test
    void constructor_nullValues_useDefaults() {
        var ep = new ApiEndpoint(1, null, null, null, null, null, null);
        assertEquals("https", ep.getScheme());
        assertEquals("GET", ep.getMethod());
        assertEquals("", ep.getServer());
        assertEquals("/", ep.getPath());
        assertTrue(ep.getParameters().isEmpty());
        assertEquals("", ep.getDescription());
    }

    @Test
    void constructor_validValues_preserved() {
        var params = List.of(new ApiEndpoint.ParameterInfo("id", "path", "1"));
        var ep = new ApiEndpoint(1, "http", "POST", "https://api.test.com", "/users", params, "Create user");
        assertEquals(1, ep.getIndex());
        assertEquals("http", ep.getScheme());
        assertEquals("POST", ep.getMethod());
        assertEquals("https://api.test.com", ep.getServer());
        assertEquals("/users", ep.getPath());
        assertEquals(1, ep.getParameters().size());
        assertEquals("Create user", ep.getDescription());
    }

    @Test
    void parameterInfo_nullPlaceholder_usesEmpty() {
        var p = new ApiEndpoint.ParameterInfo("x", "query", null);
        assertEquals("", p.getPlaceholderValue());
    }

    @Test
    void legacyConstructor_defaultsRequiredSchemesAndTagsToEmpty() {
        var ep = new ApiEndpoint(1, "https", "GET", "", "/", List.of(), "");
        assertTrue(ep.getRequiredSchemes().isEmpty());
        assertTrue(ep.getTags().isEmpty());
    }

    @Test
    void fullConstructor_preservesRequiredSchemesAndTags() {
        var ep = new ApiEndpoint(1, "https", "GET", "", "/admin", List.of(), "",
                List.of("bearerAuth", "apiKey"), List.of("Admin"));
        assertEquals(List.of("bearerAuth", "apiKey"), ep.getRequiredSchemes());
        assertEquals(List.of("Admin"), ep.getTags());
    }

    @Test
    void requiredSchemes_unmodifiable() {
        var ep = new ApiEndpoint(1, "https", "GET", "", "/", List.of(), "",
                List.of("bearerAuth"), List.of());
        assertThrows(UnsupportedOperationException.class, () -> ep.getRequiredSchemes().add("other"));
    }

    @Test
    void tags_unmodifiable() {
        var ep = new ApiEndpoint(1, "https", "GET", "", "/", List.of(), "",
                List.of(), List.of("Admin"));
        assertThrows(UnsupportedOperationException.class, () -> ep.getTags().add("Added"));
    }

    @Test
    void nullRequiredSchemesAndTags_treatedAsEmpty() {
        var ep = new ApiEndpoint(1, "https", "GET", "", "/", List.of(), "", null, null);
        assertTrue(ep.getRequiredSchemes().isEmpty());
        assertTrue(ep.getTags().isEmpty());
    }

    @Test
    void isObjectScoped_trueForTemplatedPath_evenWithoutDeclaredParameters() {
        // Path-item-level parameters are not merged into operations by the parser, and some
        // specs never declare them; the template in the path is the reliable signal.
        assertTrue(new ApiEndpoint(1, "https", "GET", "", "/users/{id}", List.of(), "").isObjectScoped());
        assertFalse(new ApiEndpoint(1, "https", "GET", "", "/users", List.of(new ApiEndpoint.ParameterInfo("q", "query", "x")), "").isObjectScoped());
        assertFalse(new ApiEndpoint(1, "https", "GET", "", "/users", List.of(), "").isObjectScoped());
    }

}
