package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class IdentityTest {

    @Test
    void constructor_blankName_rejected() {
        assertThrows(IllegalArgumentException.class, () -> new Identity("", AuthConfig.empty(), ""));
        assertThrows(IllegalArgumentException.class, () -> new Identity("   ", AuthConfig.empty(), ""));
    }

    @Test
    void constructor_nullName_rejected() {
        assertThrows(NullPointerException.class, () -> new Identity(null, AuthConfig.empty(), ""));
    }

    @Test
    void constructor_trimsName() {
        var id = new Identity("  admin  ", AuthConfig.empty(), "");
        assertEquals("admin", id.name());
    }

    @Test
    void empty_factoryYieldsEmptyAuth() {
        var id = Identity.empty("test");
        assertEquals("test", id.name());
        assertTrue(id.authConfig().isEmpty());
        assertEquals("", id.baseUrlOverride());
    }

    @Test
    void withName_returnsNewInstanceWithNewName() {
        var original = new Identity("old", AuthConfig.empty(), "https://api.example.com");
        var renamed = original.withName("new");
        assertEquals("old", original.name());
        assertEquals("new", renamed.name());
        assertEquals("https://api.example.com", renamed.baseUrlOverride());
    }

    @Test
    void roundTrip_preservesAllFields() {
        var auth = new AuthConfig(
                "eyJtoken.sig",
                "sekret", "X-API-Key", AuthConfig.ApiKeyLocation.QUERY,
                "admin", "hunter2",
                AuthConfig.parseExtraHeaders("X-Tenant: acme\nX-Trace-Id: abc-123")
        );
        var original = new Identity("admin-identity", auth, "https://api.example.com");
        var encoded = original.serialise();
        var restored = Identity.deserialise(encoded);

        assertEquals("admin-identity", restored.name());
        assertEquals("eyJtoken.sig", restored.authConfig().bearerToken());
        assertEquals("sekret", restored.authConfig().apiKeyValue());
        assertEquals("X-API-Key", restored.authConfig().apiKeyName());
        assertEquals(AuthConfig.ApiKeyLocation.QUERY, restored.authConfig().apiKeyLocation());
        assertEquals("admin", restored.authConfig().basicUser());
        assertEquals("hunter2", restored.authConfig().basicPass());
        assertEquals(2, restored.authConfig().extraHeaders().size());
        assertEquals("X-Tenant", restored.authConfig().extraHeaders().get(0).name());
        assertEquals("acme", restored.authConfig().extraHeaders().get(0).value());
        assertEquals("https://api.example.com", restored.baseUrlOverride());
    }

    @Test
    void roundTrip_emptyIdentityPreserved() {
        var original = Identity.empty("empty");
        var restored = Identity.deserialise(original.serialise());
        assertEquals(original, restored);
    }

    @Test
    void roundTrip_specialCharsInValues() {
        // Ampersands, equals signs, newlines, Unicode — must all survive.
        var auth = new AuthConfig(
                "token=with&special?chars",
                "key=val&other", "X-Weird-Name: with: colons", AuthConfig.ApiKeyLocation.HEADER,
                "user@domain", "pa\"ss=!@#",
                AuthConfig.parseExtraHeaders("X-Multi: line1\\nline2\nX-Unicode: résumé")
        );
        var original = new Identity("weird-ïdentity", auth, "https://host:8443/base=test");
        var restored = Identity.deserialise(original.serialise());
        assertEquals(original, restored);
    }

    @Test
    void deserialise_nullOrEmpty_throws() {
        assertThrows(IllegalArgumentException.class, () -> Identity.deserialise(null));
        assertThrows(IllegalArgumentException.class, () -> Identity.deserialise(""));
    }

    @Test
    void deserialise_missingName_throws() {
        String noName = "bearer=eyJ&apiKeyValue=";
        assertThrows(IllegalArgumentException.class, () -> Identity.deserialise(noName));
    }

    @Test
    void deserialise_unknownApiKeyLocation_fallsBackToHeader() {
        // Craft a payload with a bad enum value.
        String payload = "name=x&apiKeyLocation=INVALID";
        var restored = Identity.deserialise(payload);
        assertEquals(AuthConfig.ApiKeyLocation.HEADER, restored.authConfig().apiKeyLocation());
    }

    @Test
    void deserialise_unknownKeysIgnored() {
        String payload = "name=x&unknown=value&futureField=xyz";
        assertDoesNotThrow(() -> Identity.deserialise(payload));
    }

    @Test
    void deserialise_missingFieldsDefaultToEmpty() {
        String minimal = "name=minimal";
        var restored = Identity.deserialise(minimal);
        assertEquals("minimal", restored.name());
        assertTrue(restored.authConfig().isEmpty());
        assertEquals("", restored.baseUrlOverride());
    }

    @Test
    void equals_sameFieldsAreEqual() {
        var a = new Identity("x", new AuthConfig("tok", null, null, null, null, null), "u");
        var b = new Identity("x", new AuthConfig("tok", null, null, null, null, null), "u");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void equals_differentNameNotEqual() {
        var a = Identity.empty("a");
        var b = Identity.empty("b");
        assertNotEquals(a, b);
    }

    @Test
    void equals_differentAuthNotEqual() {
        var a = new Identity("x", new AuthConfig("tok1", null, null, null, null, null), "");
        var b = new Identity("x", new AuthConfig("tok2", null, null, null, null, null), "");
        assertNotEquals(a, b);
    }

    @Test
    void equals_differentBaseUrlNotEqual() {
        var a = new Identity("x", AuthConfig.empty(), "https://a.example.com");
        var b = new Identity("x", AuthConfig.empty(), "https://b.example.com");
        assertNotEquals(a, b);
    }

    @Test
    void equals_nullOrWrongTypeReturnsFalse() {
        var a = Identity.empty("x");
        assertNotEquals(a, null);
        assertNotEquals(a, "string");
        assertEquals(a, a);
    }
}
