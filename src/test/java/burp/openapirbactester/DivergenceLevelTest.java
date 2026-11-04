package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DivergenceLevelTest {

    private static RbacCellResult ok(int status) { return RbacCellResult.ok(status, 0, 0); }
    private static RbacCellResult err() { return RbacCellResult.error("boom", 0); }

    @Test
    void nullOrEmpty_isUnknown() {
        assertEquals(DivergenceLevel.UNKNOWN, DivergenceLevel.classify(null));
        assertEquals(DivergenceLevel.UNKNOWN, DivergenceLevel.classify(List.of()));
    }

    @Test
    void anyNullCell_isUnknown() {
        assertEquals(DivergenceLevel.UNKNOWN,
                DivergenceLevel.classify(Arrays.asList(ok(200), null, ok(403))));
    }

    @Test
    void allErrors_isAllErrored() {
        assertEquals(DivergenceLevel.ALL_ERRORED,
                DivergenceLevel.classify(List.of(err(), err(), err())));
    }

    @Test
    void allAllowed_isConsistentAllow() {
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(List.of(ok(200), ok(204), ok(201))));
    }

    @Test
    void allDenied_isConsistentDeny() {
        assertEquals(DivergenceLevel.CONSISTENT_DENY,
                DivergenceLevel.classify(List.of(ok(401), ok(403), ok(403))));
    }

    @Test
    void monotonicSuffixAllow_isTiered() {
        // Low-priority denied, higher ones allowed — healthy role enforcement.
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(401), ok(403), ok(200))));
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(401), ok(200), ok(200))));
    }

    @Test
    void allowThenDeny_isDivergent() {
        // Low-priority got in, high-priority was denied — inversion.
        assertEquals(DivergenceLevel.DIVERGENT,
                DivergenceLevel.classify(List.of(ok(200), ok(403), ok(403))));
    }

    @Test
    void allowDenyAllow_isDivergent() {
        assertEquals(DivergenceLevel.DIVERGENT,
                DivergenceLevel.classify(List.of(ok(200), ok(401), ok(200))));
    }

    @Test
    void errorsInMiddle_skippedDuringClassification() {
        // One identity errored out; the remaining two show healthy tiering.
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(401), err(), ok(200))));
    }

    @Test
    void errorsMixedWithAllAllowed_stillConsistentAllow() {
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(List.of(ok(200), err(), ok(200))));
    }

    @Test
    void singleAllowed_isConsistentAllow() {
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(List.of(ok(200))));
    }

    @Test
    void singleDenied_isConsistentDeny() {
        assertEquals(DivergenceLevel.CONSISTENT_DENY,
                DivergenceLevel.classify(List.of(ok(403))));
    }

    @Test
    void singleError_isAllErrored() {
        assertEquals(DivergenceLevel.ALL_ERRORED,
                DivergenceLevel.classify(List.of(err())));
    }

    // ---- horizontal (same-tier / object-level) checks ---------------------------------

    private static RbacCellResult body(int status, String hash) { return RbacCellResult.ok(status, 10, 0, hash); }

    @Test
    void horizontal_twoCredentialedIdentitiesSameBody_onObjectScopedEndpoint_isPossibleIdor() {
        // anon blocked, user and admin both get byte-identical records for /users/{id}.
        var cells = List.of(body(401, "e"), body(200, "same"), body(200, "same"));
        assertEquals(DivergenceLevel.HORIZONTAL,
                DivergenceLevel.classify(cells, true, List.of(false, true, true)));
    }

    @Test
    void horizontal_notFlagged_whenBodiesDiffer() {
        var cells = List.of(body(401, "e"), body(200, "mine"), body(200, "theirs"));
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(cells, true, List.of(false, true, true)));
    }

    @Test
    void horizontal_notFlagged_whenEndpointHasNoPathParameter() {
        var cells = List.of(body(401, "e"), body(200, "same"), body(200, "same"));
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(cells, false, List.of(false, true, true)));
    }

    @Test
    void horizontal_ignoresUncredentialedIdentities() {
        // anon and user see the same body but anon has no credentials: that's "public", not IDOR.
        var cells = List.of(body(200, "same"), body(200, "same"), body(200, "other"));
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(cells, true, List.of(false, true, true)));
    }

    @Test
    void horizontal_notFlagged_whenAnonymousGotTheSameBody_objectIsPublic() {
        // Anonymous, user and admin all see the same object: public, not IDOR.
        var cells = List.of(body(200, "same"), body(200, "same"), body(200, "same"));
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(cells, true, List.of(false, true, true)));
    }

    @Test
    void horizontal_stillFlagged_whenAnonymousGotADifferentBody() {
        // Anonymous sees a stub, user and admin see the same full record.
        var cells = List.of(body(200, "stub"), body(200, "same"), body(200, "same"));
        assertEquals(DivergenceLevel.HORIZONTAL,
                DivergenceLevel.classify(cells, true, List.of(false, true, true)));
    }

    @Test
    void horizontal_ignoresCellsWithoutHash() {
        var cells = List.of(body(401, null), body(200, null), body(200, null));
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(cells, true, List.of(false, true, true)));
    }

    @Test
    void horizontal_verticalInversionStillWins() {
        var cells = List.of(body(200, "same"), body(200, "same"), body(403, "x"));
        assertEquals(DivergenceLevel.DIVERGENT,
                DivergenceLevel.classify(cells, true, List.of(true, true, true)));
    }

    @Test
    void horizontal_labelAndExplanation() {
        assertEquals("Possible IDOR", DivergenceLevel.HORIZONTAL.humanLabel());
        assertTrue(DivergenceLevel.HORIZONTAL.explanation().toLowerCase().contains("horizontal"));
    }

    @Test
    void summaryLabel_lowercasesFirstWordOnly_keepsAcronyms() {
        assertEquals("possible IDOR", DivergenceLevel.HORIZONTAL.summaryLabel());
        assertEquals("consistent allow", DivergenceLevel.CONSISTENT_ALLOW.summaryLabel());
        assertEquals("tiered", DivergenceLevel.TIERED.summaryLabel());
    }

    @Test
    void humanLabel_coversEveryEnumValue() {
        for (DivergenceLevel level : DivergenceLevel.values()) {
            String label = level.humanLabel();
            assertNotNull(label);
            assertFalse(label.isBlank(), "humanLabel should not be blank for " + level);
            assertFalse(label.contains("_"), "humanLabel should not contain underscores for " + level);
        }
    }

    @Test
    void explanation_coversEveryEnumValueAndIsSubstantive() {
        for (DivergenceLevel level : DivergenceLevel.values()) {
            String explanation = level.explanation();
            assertNotNull(explanation);
            assertTrue(explanation.length() > 20, "explanation should be a real sentence for " + level);
            assertFalse(explanation.contains("_"), "explanation should not contain enum names for " + level);
        }
    }

    @Test
    void humanLabel_specificValues() {
        assertEquals("Tiered", DivergenceLevel.TIERED.humanLabel());
        assertEquals("Divergent", DivergenceLevel.DIVERGENT.humanLabel());
        assertEquals("Consistent allow", DivergenceLevel.CONSISTENT_ALLOW.humanLabel());
        assertEquals("Consistent deny", DivergenceLevel.CONSISTENT_DENY.humanLabel());
        assertEquals("All errored", DivergenceLevel.ALL_ERRORED.humanLabel());
        assertEquals("Unknown", DivergenceLevel.UNKNOWN.humanLabel());
    }

    @Test
    void explanation_divergentMentionsInversion() {
        assertTrue(DivergenceLevel.DIVERGENT.explanation().toLowerCase().contains("inversion"),
                "DIVERGENT explanation should name the inversion pattern");
    }

    @Test
    void depthModel_403_403_404_isTiered() {
        // SuperAdmin got 404 (passed auth, no resource); others got 403 (auth-blocked).
        // Depths: 0, 0, 1 — non-decreasing, not all same → TIERED.
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(403), ok(403), ok(404))));
    }

    @Test
    void depthModel_403_404_200_isTiered() {
        // Full-stack tiering: readonly blocked, consultant gets 404, SuperAdmin 200.
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(403), ok(404), ok(200))));
    }

    @Test
    void depthModel_404_404_404_isConsistentDeny() {
        // Everyone got the same terminal outcome — resource genuinely doesn't exist.
        assertEquals(DivergenceLevel.CONSISTENT_DENY,
                DivergenceLevel.classify(List.of(ok(404), ok(404), ok(404))));
    }

    @Test
    void depthModel_422_403_403_isDivergent() {
        // Non-monotonic: the least-privileged identity got further (422 = validation,
        // but still depth 0) — actually both are depth 0 so this is all-same-depth.
        // Let's test a real inversion: 404, 403, 403 — readonly got past auth, others didn't.
        assertEquals(DivergenceLevel.DIVERGENT,
                DivergenceLevel.classify(List.of(ok(404), ok(403), ok(403))));
    }

    @Test
    void depthModel_3xxTreatedLikeAllow() {
        // 301/302 usually means "you're authenticated and redirected somewhere legit".
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW,
                DivergenceLevel.classify(List.of(ok(302), ok(302), ok(301))));
    }

    @Test
    void depthModel_mixOf401And403_isConsistentDeny() {
        // Both are "blocked at auth" — same depth, so consistent.
        assertEquals(DivergenceLevel.CONSISTENT_DENY,
                DivergenceLevel.classify(List.of(ok(401), ok(403), ok(403))));
    }

    @Test
    void depthModel_500_500_404_isTiered() {
        // Server errors are treated as depth 0; one identity got to depth 1.
        assertEquals(DivergenceLevel.TIERED,
                DivergenceLevel.classify(List.of(ok(500), ok(500), ok(404))));
    }

    @Test
    void depthModel_200_403_200_isDivergent() {
        // Middle identity denied — flanking identities got through.
        assertEquals(DivergenceLevel.DIVERGENT,
                DivergenceLevel.classify(List.of(ok(200), ok(403), ok(200))));
    }
}
