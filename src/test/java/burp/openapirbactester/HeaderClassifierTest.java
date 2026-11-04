package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HeaderClassifierTest {

    @Test
    void authorizationBearer_routedToBearerField() {
        var ex = HeaderClassifier.fromRawHeaderLines(List.of("Authorization: Bearer eyJtoken.sig"));
        assertEquals("eyJtoken.sig", ex.bearerToken());
        assertTrue(ex.extraHeaders().isEmpty());
    }

    @Test
    void authorizationBasic_decodedIntoUserPass() {
        var ex = HeaderClassifier.fromRawHeaderLines(List.of("Authorization: Basic YWRtaW46aHVudGVyMg=="));
        assertEquals("admin", ex.basicUser());
        assertEquals("hunter2", ex.basicPass());
        assertNull(ex.bearerToken());
        assertTrue(ex.extraHeaders().isEmpty());
    }

    @Test
    void authorizationCustomScheme_keptInExtras() {
        var ex = HeaderClassifier.fromRawHeaderLines(List.of("Authorization: X-API-Key lp_abc123"));
        assertNull(ex.bearerToken());
        assertNull(ex.basicUser());
        assertEquals(1, ex.extraHeaders().size());
        assertEquals("Authorization", ex.extraHeaders().get(0).name());
        assertEquals("X-API-Key lp_abc123", ex.extraHeaders().get(0).value());
    }

    @Test
    void authorizationBasic_malformedFallsThroughToExtras() {
        var ex = HeaderClassifier.fromRawHeaderLines(List.of("Authorization: Basic !!not-base64!!"));
        assertNull(ex.basicUser());
        assertEquals(1, ex.extraHeaders().size());
    }

    @Test
    void xApiKey_routedToApiKeyFields() {
        var ex = HeaderClassifier.fromRawHeaderLines(List.of("X-API-Key: sekret123"));
        assertEquals("X-API-Key", ex.apiKeyName());
        assertEquals("sekret123", ex.apiKeyValue());
        assertTrue(ex.extraHeaders().isEmpty());
    }

    @Test
    void denylistedHeaders_dropped() {
        var ex = HeaderClassifier.fromRawHeaderLines(List.of(
                "Host: example.com",
                "User-Agent: Mozilla/5.0",
                "Accept: */*",
                "Accept-Encoding: gzip",
                "Accept-Language: en",
                "Connection: keep-alive",
                "Content-Type: application/json",
                "Content-Length: 42",
                "Referer: https://evil.com",
                "Origin: https://evil.com",
                "Sec-Ch-Ua: Chromium",
                "Sec-Fetch-Mode: cors",
                "Priority: u=1, i",
                "X-Pwnfox-Color: blue"
        ));
        assertTrue(ex.extraHeaders().isEmpty(), "denylisted headers should be dropped");
    }

    @Test
    void customHeaders_preservedInExtras() {
        var ex = HeaderClassifier.fromRawHeaderLines(List.of(
                "Host: example.com",
                "X-Tenant: acme",
                "X-Trace-Id: abc-123",
                "Cookie: session=eyJ; csrf_token=xyz"
        ));
        assertEquals(3, ex.extraHeaders().size());
        assertEquals("X-Tenant", ex.extraHeaders().get(0).name());
        assertEquals("X-Trace-Id", ex.extraHeaders().get(1).name());
        assertEquals("Cookie", ex.extraHeaders().get(2).name());
        assertEquals("session=eyJ; csrf_token=xyz", ex.extraHeaders().get(2).value());
    }

    @Test
    void isSpecUrlPath_matchesCommonVariants() {
        assertTrue(HeaderClassifier.isSpecUrlPath("/openapi.json"));
        assertTrue(HeaderClassifier.isSpecUrlPath("/api/openapi.json"));
        assertTrue(HeaderClassifier.isSpecUrlPath("/v3/api-docs"));
        assertTrue(HeaderClassifier.isSpecUrlPath("/SWAGGER.yaml"));
        assertTrue(HeaderClassifier.isSpecUrlPath("/openapi.json?cache=1"));
        assertFalse(HeaderClassifier.isSpecUrlPath("/api/users"));
        assertFalse(HeaderClassifier.isSpecUrlPath(null));
    }

    @Test
    void looksLikeSpecBody_jsonDetection() {
        assertTrue(HeaderClassifier.looksLikeSpecBody("{\"openapi\":\"3.0.0\",\"info\":{}}"));
        assertTrue(HeaderClassifier.looksLikeSpecBody("  { \"swagger\": \"2.0\" }"));
        assertFalse(HeaderClassifier.looksLikeSpecBody("{\"error\":\"not authorized\"}"));
        assertFalse(HeaderClassifier.looksLikeSpecBody("<html><body>login</body></html>"));
    }

    @Test
    void looksLikeSpecBody_yamlDetection() {
        assertTrue(HeaderClassifier.looksLikeSpecBody("openapi: 3.0.0\ninfo: {}"));
        assertTrue(HeaderClassifier.looksLikeSpecBody("swagger: \"2.0\""));
        assertFalse(HeaderClassifier.looksLikeSpecBody("name: widget\nversion: 1"));
    }

    @Test
    void looksLikeSpecBody_rejectsNullAndBlank() {
        assertFalse(HeaderClassifier.looksLikeSpecBody(null));
        assertFalse(HeaderClassifier.looksLikeSpecBody(""));
        assertFalse(HeaderClassifier.looksLikeSpecBody("   \n  "));
    }
}
