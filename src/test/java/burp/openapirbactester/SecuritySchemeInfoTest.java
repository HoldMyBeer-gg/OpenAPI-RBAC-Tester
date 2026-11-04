package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecuritySchemeInfoTest {

    @Test
    void bearer_factoryCapturesNameAndFormat() {
        var s = SecuritySchemeInfo.bearer("bearerAuth", "JWT");
        assertEquals("bearerAuth", s.name());
        assertEquals(SecuritySchemeInfo.SchemeType.BEARER, s.type());
        assertEquals("JWT", s.bearerFormat());
        assertNull(s.apiKeyName());
        assertNull(s.apiKeyLocation());
    }

    @Test
    void apiKey_factoryCapturesLocationAndHeaderName() {
        var s = SecuritySchemeInfo.apiKey("keyAuth", "header", "X-API-Key");
        assertEquals(SecuritySchemeInfo.SchemeType.API_KEY, s.type());
        assertEquals("header", s.apiKeyLocation());
        assertEquals("X-API-Key", s.apiKeyName());
        assertNull(s.bearerFormat());
    }

    @Test
    void displayName_bearerWithFormat() {
        assertEquals("Bearer (JWT)", SecuritySchemeInfo.bearer("x", "JWT").displayName());
    }

    @Test
    void displayName_bearerWithoutFormat() {
        assertEquals("Bearer", SecuritySchemeInfo.bearer("x", null).displayName());
        assertEquals("Bearer", SecuritySchemeInfo.bearer("x", "").displayName());
    }

    @Test
    void displayName_apiKeyUsesHeaderNameWhenPresent() {
        assertEquals("X-API-Key (header)",
                SecuritySchemeInfo.apiKey("keyAuth", "header", "X-API-Key").displayName());
    }

    @Test
    void displayName_apiKeyFallsBackToSchemeNameWhenHeaderNameMissing() {
        assertEquals("keyAuth (query)",
                SecuritySchemeInfo.apiKey("keyAuth", "query", null).displayName());
    }

    @Test
    void displayName_basicOauthOidcOther() {
        assertEquals("Basic", SecuritySchemeInfo.basic("basicAuth").displayName());
        assertEquals("OAuth2", SecuritySchemeInfo.oauth2("oauth2Scheme").displayName());
        assertEquals("OpenID Connect", SecuritySchemeInfo.openIdConnect("oidc").displayName());
        assertEquals("weirdCustom", SecuritySchemeInfo.other("weirdCustom").displayName());
    }
}
