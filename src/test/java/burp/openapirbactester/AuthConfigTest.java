package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AuthConfigTest {

    @Test
    void empty_reportsEverythingAbsent() {
        AuthConfig a = AuthConfig.empty();
        assertTrue(a.isEmpty());
        assertFalse(a.hasBearer());
        assertFalse(a.hasApiKey());
        assertFalse(a.hasBasic());
    }

    @Test
    void bearerToken_whitespaceStripped() {
        AuthConfig a = new AuthConfig("  eyJhbGciOi.JI UzI1NiJ9 \n.signature \r\n", null, null, null, null, null);
        assertTrue(a.hasBearer());
        assertEquals("eyJhbGciOi.JIUzI1NiJ9.signature", a.bearerToken());
    }

    @Test
    void apiKey_requiresBothValueAndName() {
        assertFalse(new AuthConfig(null, "secret", "", null, null, null).hasApiKey());
        assertFalse(new AuthConfig(null, "", "X-API-Key", null, null, null).hasApiKey());
        assertTrue(new AuthConfig(null, "secret", "X-API-Key", null, null, null).hasApiKey());
    }

    @Test
    void apiKeyLocation_defaultsToHeader() {
        AuthConfig a = new AuthConfig(null, "s", "X", null, null, null);
        assertEquals(AuthConfig.ApiKeyLocation.HEADER, a.apiKeyLocation());
    }

    @Test
    void basic_encodesUserPassAsBase64() {
        AuthConfig a = new AuthConfig(null, null, null, null, "admin", "hunter2");
        String expected = "Basic " + Base64.getEncoder().encodeToString("admin:hunter2".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, a.basicAuthorizationHeaderValue());
        assertTrue(a.hasBasic());
    }

    @Test
    void basic_emptyPassStillEncodesColon() {
        AuthConfig a = new AuthConfig(null, null, null, null, "admin", "");
        assertTrue(a.basicAuthorizationHeaderValue().startsWith("Basic "));
        String decoded = new String(Base64.getDecoder().decode(a.basicAuthorizationHeaderValue().substring(6)),
                StandardCharsets.UTF_8);
        assertEquals("admin:", decoded);
    }

    @Test
    void parseExtraHeaders_splitsOnColonAndDropsLeadingSpace() {
        var headers = AuthConfig.parseExtraHeaders("X-Tenant: acme\nX-Trace-Id:abc123");
        assertEquals(2, headers.size());
        assertEquals("X-Tenant", headers.get(0).name());
        assertEquals("acme", headers.get(0).value());
        assertEquals("X-Trace-Id", headers.get(1).name());
        assertEquals("abc123", headers.get(1).value());
    }

    @Test
    void parseExtraHeaders_preservesInternalColons() {
        var headers = AuthConfig.parseExtraHeaders("X-Forwarded-For: 10.0.0.1:8080");
        assertEquals("10.0.0.1:8080", headers.get(0).value());
    }

    @Test
    void parseExtraHeaders_ignoresBlanksAndMalformed() {
        var headers = AuthConfig.parseExtraHeaders("\n\nX-Good: ok\ninvalidline\n:novalue\n   \nX-Also: yes\n");
        assertEquals(2, headers.size());
        assertEquals("X-Good", headers.get(0).name());
        assertEquals("X-Also", headers.get(1).name());
    }

    @Test
    void parseExtraHeaders_nullOrBlank_returnsEmpty() {
        assertTrue(AuthConfig.parseExtraHeaders(null).isEmpty());
        assertTrue(AuthConfig.parseExtraHeaders("").isEmpty());
        assertTrue(AuthConfig.parseExtraHeaders("   \n  ").isEmpty());
    }

    @Test
    void extraHeaders_makeConfigNonEmpty() {
        AuthConfig a = new AuthConfig(null, null, null, null, null, null,
                AuthConfig.parseExtraHeaders("X-Foo: bar"));
        assertFalse(a.isEmpty());
        assertEquals(1, a.extraHeaders().size());
    }

    @Test
    void basicUserAndPass_gettersExposeInputs() {
        AuthConfig a = new AuthConfig(null, null, null, null, "admin", "hunter2");
        assertEquals("admin", a.basicUser());
        assertEquals("hunter2", a.basicPass());
    }

    @Test
    void hasCredentials_distinguishesAuthHeadersFromBrowserNoise() {
        assertFalse(AuthConfig.empty().hasCredentials());
        assertTrue(new AuthConfig("tok", null, null, null, null, null).hasCredentials());
        assertTrue(new AuthConfig(null, "k", "X-API-Key", null, null, null).hasCredentials());
        assertTrue(new AuthConfig(null, null, null, null, "bob", "pw").hasCredentials());

        AuthConfig noise = new AuthConfig(null, null, null, null, null, null, java.util.List.of(
                new AuthConfig.HeaderPair("X-Requested-With", "XMLHttpRequest"),
                new AuthConfig.HeaderPair("Sec-GPC", "1"),
                new AuthConfig.HeaderPair("X-Tenant", "acme")));
        assertFalse(noise.hasCredentials(), "non-auth extra headers are not credentials");

        for (String name : java.util.List.of("Cookie", "Authorization", "Proxy-Authorization",
                "X-Auth-Token", "X-Session-Id", "X-Api-Key", "X-Access-JWT", "x-csrf-token")) {
            AuthConfig c = new AuthConfig(null, null, null, null, null, null,
                    java.util.List.of(new AuthConfig.HeaderPair(name, "v")));
            assertTrue(c.hasCredentials(), name + " should count as a credential");
        }
    }
}
