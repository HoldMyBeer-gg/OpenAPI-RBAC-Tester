package burp.openapirbactester;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RequestGenerator}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class RequestGeneratorTest {

    private RequestGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new RequestGenerator();
    }

    @Test
    void buildRequestBytes_simpleGet() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("GET /users HTTP/1.1"));
        assertTrue(req.contains("Host: api.test.com"));
    }

    @Test
    void buildRequestBytes_baseUrlOverride() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://spec.example.com", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, "https://target.example.com");
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: target.example.com"));
    }

    @Test
    void buildRequestBytes_pathParamsSubstituted() {
        var params = List.of(new ApiEndpoint.ParameterInfo("id", "path", "1"));
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}", params, "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        assertTrue(new String(raw, StandardCharsets.UTF_8).contains("/users/1"));
    }

    @Test
    void buildRequestBytes_postWithBody() {
        var ep = new ApiEndpoint(1, "https", "POST", "https://api.test.com", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Content-Type: application/json"));
        assertTrue(req.contains("{}"));
    }

    @Test
    void substitutePathParams_remainingBracesReplaced() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}/posts/{postId}",
                List.of(new ApiEndpoint.ParameterInfo("id", "path", "1")), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String s = new String(raw, StandardCharsets.UTF_8);
        assertTrue(s.contains("/users/1/posts/1"));
    }

    @Test
    void buildRequestBytes_queryParams() {
        var params = List.of(
                new ApiEndpoint.ParameterInfo("limit", "query", "10"),
                new ApiEndpoint.ParameterInfo("offset", "query", "0")
        );
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", params, "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("limit=10"));
        assertTrue(req.contains("offset=0"));
        assertTrue(req.contains("&"));
    }

    @Test
    void buildRequestBytes_putWithBody() {
        var ep = new ApiEndpoint(1, "https", "PUT", "https://api.test.com", "/users/1", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("PUT /users/1 HTTP/1.1"));
        assertTrue(req.contains("Content-Type: application/json"));
        assertTrue(req.contains("{}"));
    }

    @Test
    void buildRequestBytes_patchWithBody() {
        var ep = new ApiEndpoint(1, "https", "PATCH", "https://api.test.com", "/users/1", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("PATCH /users/1 HTTP/1.1"));
        assertTrue(req.contains("Content-Type: application/json"));
    }

    @Test
    void buildRequestBytes_nonStandardPort() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com:8443", "/api", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: api.test.com:8443"));
    }

    @Test
    void buildRequestBytes_httpDefaultPort() {
        var ep = new ApiEndpoint(1, "http", "GET", "http://api.test.com", "/api", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: api.test.com"));
        assertFalse(req.contains(":80"));
    }

    @Test
    void buildRequestBytes_emptyServer_usesLocalhost() {
        var ep = new ApiEndpoint(1, "https", "GET", "", "/api", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: localhost"));
    }

    @Test
    void buildRequestBytes_serverWithTrailingSlash() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com/", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("GET /users HTTP/1.1"));
        assertFalse(req.contains("//users"));
    }

    @Test
    void buildRequestBytes_bearerTokenInjected() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig("eyJtoken", null, null, null, null, null);
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        assertTrue(req.contains("Authorization: Bearer eyJtoken\r\n"));
    }

    @Test
    void buildRequestBytes_bearerTokenWhitespaceStripped() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig("eyJ\nabc.def\r\n ghi", null, null, null, null, null);
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        assertTrue(req.contains("Authorization: Bearer eyJabc.defghi\r\n"));
    }

    @Test
    void buildRequestBytes_apiKeyAsHeader() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig(null, "abc123", "X-API-Key", AuthConfig.ApiKeyLocation.HEADER, null, null);
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        assertTrue(req.contains("X-API-Key: abc123\r\n"));
    }

    @Test
    void buildRequestBytes_apiKeyAsQuery_urlEncoded() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig(null, "abc 123+x", "api key", AuthConfig.ApiKeyLocation.QUERY, null, null);
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        assertTrue(req.contains("/users?api+key=abc+123%2Bx"));
    }

    @Test
    void buildRequestBytes_apiKeyAsQuery_appendsToExistingQuery() {
        var params = List.of(new ApiEndpoint.ParameterInfo("limit", "query", "10"));
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", params, "");
        AuthConfig auth = new AuthConfig(null, "secret", "key", AuthConfig.ApiKeyLocation.QUERY, null, null);
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        assertTrue(req.contains("/users?limit=10&key=secret"));
    }

    @Test
    void buildRequestBytes_apiKeyAsCookie() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig(null, "sessval", "sid", AuthConfig.ApiKeyLocation.COOKIE, null, null);
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        assertTrue(req.contains("Cookie: sid=sessval\r\n"));
    }

    @Test
    void buildRequestBytes_basicAuthInjected() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig(null, null, null, null, "admin", "hunter2");
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        String expected = "Authorization: Basic " +
                java.util.Base64.getEncoder().encodeToString("admin:hunter2".getBytes(StandardCharsets.UTF_8));
        assertTrue(req.contains(expected + "\r\n"));
    }

    @Test
    void buildRequestBytes_emptyAuth_addsNoAuthHeaders() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        String req = new String(generator.buildRequestBytes(ep, null, AuthConfig.empty()), StandardCharsets.UTF_8);
        assertFalse(req.contains("Authorization:"));
        assertFalse(req.contains("Cookie:"));
        assertFalse(req.contains("X-API-Key:"));
    }

    @Test
    void buildRequestBytes_nullAuth_addsNoAuthHeaders() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        String req = new String(generator.buildRequestBytes(ep, null, null), StandardCharsets.UTF_8);
        assertFalse(req.contains("Authorization:"));
    }

    @Test
    void buildRequestBytes_extraHeaders_appendedInOrder() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig(null, null, null, null, null, null,
                AuthConfig.parseExtraHeaders("X-Tenant: acme\nX-Trace-Id: abc"));
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        int tenantIdx = req.indexOf("X-Tenant: acme\r\n");
        int traceIdx = req.indexOf("X-Trace-Id: abc\r\n");
        assertTrue(tenantIdx > 0);
        assertTrue(traceIdx > tenantIdx);
    }

    @Test
    void buildRequestBytes_extraHeaders_appendedAfterAuth() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        AuthConfig auth = new AuthConfig("tok", null, null, null, null, null,
                AuthConfig.parseExtraHeaders("Authorization: override-me"));
        String req = new String(generator.buildRequestBytes(ep, null, auth), StandardCharsets.UTF_8);
        int firstAuth = req.indexOf("Authorization: Bearer tok");
        int overrideAuth = req.indexOf("Authorization: override-me");
        assertTrue(firstAuth > 0);
        assertTrue(overrideAuth > firstAuth);
    }
}
