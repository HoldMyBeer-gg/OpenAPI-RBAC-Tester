package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DestructiveEndpointDetectorTest {

    private static ApiEndpoint ep(String method, String path) {
        return new ApiEndpoint(1, "https", method, "https://api.test.com", path, List.of(), "");
    }

    @Test
    void deleteMethod_flaggedRegardlessOfPath() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("DELETE", "/api/users/1")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("DELETE", "/")));
        assertEquals("DELETE method",
                DestructiveEndpointDetector.reasonFor(ep("DELETE", "/api/anything")));
    }

    @Test
    void deleteMethodMixedCase_flagged() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("delete", "/x")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("Delete", "/x")));
    }

    @Test
    void logoutPath_flaggedWithSessionReason() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/logout")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("GET", "/auth/logout")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/logout")));
        String reason = DestructiveEndpointDetector.reasonFor(ep("POST", "/api/logout"));
        assertTrue(reason.contains("logout"), "reason should mention logout");
    }

    @Test
    void signoutVariants_allFlagged() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/signout")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/sign-out")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/log-out")));
    }

    @Test
    void revokeEndpoint_flagged() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/oauth/revoke")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/tokens/revoke")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/auth/revocation")));
    }

    @Test
    void disableOrDeactivate_flagged() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/users/1/disable")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/accounts/deactivate")));
    }

    @Test
    void destroyPurgeWipe_flagged() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/destroy")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/cache/purge")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/wipe")));
    }

    @Test
    void impersonateAssume_flagged() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/admin/impersonate/1")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/role/assume")));
    }

    @Test
    void harmlessEndpoints_notFlagged() {
        assertFalse(DestructiveEndpointDetector.isLikelyDestructive(ep("GET", "/api/users")));
        assertFalse(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/api/users")));
        assertFalse(DestructiveEndpointDetector.isLikelyDestructive(ep("PUT", "/api/users/1")));
        assertFalse(DestructiveEndpointDetector.isLikelyDestructive(ep("PATCH", "/api/users/1")));
    }

    @Test
    void substringMatches_notFlaggedAsSegment() {
        // These paths contain the danger words as substrings but not segments — shouldn't fire.
        assertFalse(DestructiveEndpointDetector.isLikelyDestructive(ep("GET", "/api/revoked-tokens")),
                "revoked (as substring in word) should not match");
        // "/payloads" does not contain "logout" anywhere. Check a real false-positive candidate.
        // "/api/purgery" contains "purge" as a substring — should this match? Our current impl
        // uses word-boundary matching, so no.
        assertFalse(DestructiveEndpointDetector.isLikelyDestructive(ep("GET", "/api/purgery")),
                "purgery (purge as sub-word) should not match");
        // But purge as a clear segment should match:
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/purge/now")));
    }

    @Test
    void trailingAndLeadingPunctuation_handled() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/logout/")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/logout?redirect=/home")));
    }

    @Test
    void caseInsensitivePathMatching() {
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/API/LOGOUT")));
        assertTrue(DestructiveEndpointDetector.isLikelyDestructive(ep("POST", "/Api/Revoke")));
    }

    @Test
    void reasonFor_harmlessEndpoint_returnsEmpty() {
        assertEquals("", DestructiveEndpointDetector.reasonFor(ep("GET", "/api/users")));
    }

    @Test
    void reasonFor_nullEndpoint_returnsEmpty() {
        assertEquals("", DestructiveEndpointDetector.reasonFor(null));
    }

    @Test
    void isLikelyDestructive_nullEndpoint_returnsFalse() {
        assertFalse(DestructiveEndpointDetector.isLikelyDestructive(null));
    }

    @Test
    void reasonFor_pathCategory_specificReasons() {
        assertEquals("logout endpoint — would invalidate comparison sessions",
                DestructiveEndpointDetector.reasonFor(ep("POST", "/api/logout")));
        assertEquals("token revocation — may invalidate credentials mid-run",
                DestructiveEndpointDetector.reasonFor(ep("POST", "/oauth/revoke")));
        assertEquals("disables/deactivates resources",
                DestructiveEndpointDetector.reasonFor(ep("POST", "/api/disable")));
        assertEquals("destroy/purge/wipe endpoint",
                DestructiveEndpointDetector.reasonFor(ep("POST", "/api/purge")));
        assertEquals("impersonation — swaps server-side identity context",
                DestructiveEndpointDetector.reasonFor(ep("POST", "/api/impersonate/1")));
    }

    @Test
    void pathLooksDestructive_nullReturnsFalse() {
        assertFalse(DestructiveEndpointDetector.pathLooksDestructive(null));
    }
}
