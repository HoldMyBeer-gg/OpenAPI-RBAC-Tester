package burp.openapirbactester;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OpenAPIParser}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class OpenAPIParserTest {

    private OpenAPIParser parser;

    @BeforeEach
    void setUp() {
        parser = new OpenAPIParser();
    }

    @Test
    void parse_emptyContent_returnsError() {
        var result = parser.parse("test", null);
        assertTrue(result.getEndpoints().isEmpty());
        assertFalse(result.getMessages().isEmpty());
        assertTrue(result.getMessages().get(0).contains("empty"));
    }

    @Test
    void parse_blankContent_returnsError() {
        var result = parser.parse("test", "   ");
        assertTrue(result.getEndpoints().isEmpty());
        assertTrue(result.getMessages().stream().anyMatch(m -> m.contains("empty")));
    }

    @Test
    void parse_invalidJson_returnsError() {
        var result = parser.parse("test", "{ invalid }");
        assertTrue(result.getEndpoints().isEmpty());
        assertFalse(result.getMessages().isEmpty());
    }

    @Test
    void parse_validOpenAPI_returnsEndpoints() throws Exception {
        String json = readResource("openapi-petstore.json");
        var result = parser.parse("petstore.json", json);
        assertFalse(result.getEndpoints().isEmpty());
        assertEquals("https://petstore.example.com/v1", result.getDefaultServer());
        assertEquals(3, result.getEndpoints().size());
        var ep = result.getEndpoints().get(0);
        assertEquals("GET", ep.getMethod());
        assertEquals("/pets", ep.getPath());
        assertEquals("https", ep.getScheme());
    }

    @Test
    void parse_pathParamsExtracted() throws Exception {
        String json = readResource("openapi-petstore.json");
        var result = parser.parse("test", json);
        var petsId = result.getEndpoints().stream()
                .filter(e -> e.getPath().contains("{id}"))
                .findFirst().orElseThrow();
        assertEquals(1, petsId.getParameters().size());
        assertEquals("id", petsId.getParameters().get(0).getName());
        assertEquals("path", petsId.getParameters().get(0).getLocation());
    }

    @Test
    void parse_queryParamsExtracted() throws Exception {
        String json = readResource("openapi-petstore.json");
        var result = parser.parse("test", json);
        var listPets = result.getEndpoints().stream()
                .filter(e -> e.getPath().equals("/pets") && "GET".equals(e.getMethod()))
                .findFirst().orElseThrow();
        assertEquals(1, listPets.getParameters().size());
        assertEquals("query", listPets.getParameters().get(0).getLocation());
    }

    @Test
    void parse_serverUrlNormalized() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[{"url":"https://api.example.com/"}],"paths":{"/":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertEquals("https://api.example.com", result.getDefaultServer());
    }

    @Test
    void parse_noServers_returnsEmptyServer() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"paths":{"/health":{}}}
            """;
        var result = parser.parse("test", json);
        assertTrue(result.getEndpoints().isEmpty());
        assertEquals("", result.getDefaultServer());
    }

    @Test
    void parse_yamlSpec_returnsEndpoints() throws Exception {
        String yaml = readResource("openapi-sample.yaml");
        var result = parser.parse("pasted", yaml);
        assertFalse(result.getEndpoints().isEmpty(), "Expected endpoints; messages: " + result.getMessages());
        assertEquals("https://api.example.com", result.getDefaultServer());
        assertTrue(result.getEndpoints().stream().anyMatch(e -> e.getPath().equals("/serviceability") && "GET".equals(e.getMethod())));
        assertTrue(result.getEndpoints().stream().anyMatch(e -> e.getPath().equals("/address/check/v1") && "POST".equals(e.getMethod())));
    }

    @Test
    void parse_yamlWithLeadingShellPrompt_stripsAndParses() throws Exception {
        String yaml = readResource("openapi-sample.yaml");
        String withPrompt = "anon@MBPC:/mnt/d$ cat openapi.json\n" + yaml;
        var result = parser.parse("pasted", withPrompt);
        assertFalse(result.getEndpoints().isEmpty(), "Expected endpoints; messages: " + result.getMessages());
        assertEquals("https://api.example.com", result.getDefaultServer());
    }

    @Test
    void parse_serverUrlWithoutScheme_handlesGracefully() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[{"url":"api.example.com"}],"paths":{"/test":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertFalse(result.getEndpoints().isEmpty());
    }

    @Test
    void parse_multipleServers_usesFirst() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[{"url":"https://api.example.com"},{"url":"https://api2.example.com"}],"paths":{"/test":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertEquals("https://api.example.com", result.getDefaultServer());
    }

    @Test
    void parse_operationWithoutParameters_returnsEndpoint() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"paths":{"/simple":{"get":{"summary":"Simple endpoint"}}}}
            """;
        var result = parser.parse("test", json);
        assertFalse(result.getEndpoints().isEmpty());
        assertEquals("Simple endpoint", result.getEndpoints().get(0).getDescription());
    }

    @Test
    void parse_operationWithDescription_usesDescription() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"paths":{"/test":{"get":{"description":"Detailed description"}}}}
            """;
        var result = parser.parse("test", json);
        assertEquals("Detailed description", result.getEndpoints().get(0).getDescription());
    }

    @Test
    void parse_httpScheme_extractsHttp() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[{"url":"http://api.example.com"}],"paths":{"/test":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertEquals("http", result.getEndpoints().get(0).getScheme());
    }

    @Test
    void parse_jsonWithBracePrefix_stripsProperly() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"paths":{"/test":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertFalse(result.getEndpoints().isEmpty());
    }

    @Test
    void parse_headerAndCookieParameters_extracted() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"paths":{"/test":{"get":{
            "parameters":[
                {"name":"Authorization","in":"header"},
                {"name":"session","in":"cookie"}
            ]
            }}}}
            """;
        var result = parser.parse("test", json);
        assertEquals(1, result.getEndpoints().size());
        var params = result.getEndpoints().get(0).getParameters();
        assertEquals(2, params.size());
        assertTrue(params.stream().anyMatch(p -> "header".equals(p.getLocation()) && "Authorization".equals(p.getName())));
        assertTrue(params.stream().anyMatch(p -> "cookie".equals(p.getLocation()) && "session".equals(p.getName())));
    }

    @Test
    void parse_malformedServerUrl_handlesGracefully() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[{"url":"ht!tp://invalid url with spaces"}],"paths":{"/test":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertFalse(result.getEndpoints().isEmpty());
        // Should use default https scheme when URL parsing fails
        assertEquals("https", result.getEndpoints().get(0).getScheme());
    }

    @Test
    void parse_emptyServersList_usesDefaultServer() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[],"paths":{"/test":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertEquals("", result.getDefaultServer());
    }

    @Test
    void parse_serverUrlWithOnlySlash_normalized() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[{"url":"/"}],"paths":{"/test":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertEquals("", result.getDefaultServer());
    }

    @Test
    void parse_emptyStringContent_returnsError() {
        var result = parser.parse("test", "");
        assertTrue(result.getEndpoints().isEmpty());
        assertFalse(result.getMessages().isEmpty());
    }

    @Test
    void parse_contentWithoutOpenAPIPrefix_parsedAsIs() {
        // Content that doesn't start with openapi:, swagger:, or { should be returned as-is and fail parsing
        String invalidContent = "This is not an OpenAPI spec at all\njust some random text";
        var result = parser.parse("test", invalidContent);
        assertTrue(result.getEndpoints().isEmpty());
        assertFalse(result.getMessages().isEmpty());
    }

    @Test
    void parse_corruptedJson_returnsErrorWithoutMessages() {
        // Completely broken JSON that makes parser return null without helpful messages
        String corrupt = "{\"broken\":}";
        var result = parser.parse("test", corrupt);
        assertTrue(result.getEndpoints().isEmpty());
        assertFalse(result.getMessages().isEmpty());
    }

    @Test
    void parse_openApiWithoutPaths_returnsEmpty() {
        // Valid OpenAPI structure but missing paths entirely
        String json = """
            {"openapi":"3.0.0","info":{"title":"Test","version":"1.0"}}
            """;
        var result = parser.parse("test", json);
        assertTrue(result.getEndpoints().isEmpty());
        // Should still parse successfully, just no endpoints
    }

    private String readResource(String name) throws Exception {
        try (InputStream is = OpenAPIParserTest.class.getResourceAsStream("/" + name)) {
            assert is != null : "Resource not found: " + name;
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
