package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AccessRuleSetTest {

    @Test
    void empty_hasNoExpectations() {
        var rs = AccessRuleSet.empty();
        assertTrue(rs.isEmpty());
        assertEquals(AccessRuleSet.Expectation.UNKNOWN,
                rs.expectationFor(List.of("Admin"), "admin"));
    }

    @Test
    void expectation_adminRule_adminAllowed_userDenied() {
        var rs = AccessRuleSet.parse("Admin -> admin*");
        assertEquals(AccessRuleSet.Expectation.EXPECT_ALLOW,
                rs.expectationFor(List.of("Admin"), "admin-jwt"));
        assertEquals(AccessRuleSet.Expectation.EXPECT_DENY,
                rs.expectationFor(List.of("Admin"), "user"));
    }

    @Test
    void expectation_noMatchingRule_unknown() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        assertEquals(AccessRuleSet.Expectation.UNKNOWN,
                rs.expectationFor(List.of("Users"), "admin"));
    }

    @Test
    void expectation_multipleRulesOneAllowsSufficient() {
        // Two matching rules: one denies, one allows → overall ALLOW (union across matched rules).
        var rs = AccessRuleSet.parse("""
                Admin -> admin
                Admin -> user
                """);
        assertEquals(AccessRuleSet.Expectation.EXPECT_ALLOW,
                rs.expectationFor(List.of("Admin"), "user"));
    }

    @Test
    void expectation_matchingRulesAllDeny_expectDeny() {
        var rs = AccessRuleSet.parse("""
                Admin -> admin
                Internal -> service-*
                """);
        assertEquals(AccessRuleSet.Expectation.EXPECT_DENY,
                rs.expectationFor(List.of("Admin", "Internal"), "anon"));
    }

    @Test
    void assess_expectAllowAndGot2xx_isOk() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        var cell = RbacCellResult.ok(200, 0, 0);
        assertEquals(AccessRuleSet.Assessment.OK,
                rs.assess(List.of("Admin"), "admin", cell));
    }

    @Test
    void assess_expectAllowButGot403_isViolation() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        var cell = RbacCellResult.ok(403, 0, 0);
        assertEquals(AccessRuleSet.Assessment.VIOLATION,
                rs.assess(List.of("Admin"), "admin", cell));
    }

    @Test
    void assess_expectDenyButGot200_isViolation() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        var cell = RbacCellResult.ok(200, 0, 0);
        assertEquals(AccessRuleSet.Assessment.VIOLATION,
                rs.assess(List.of("Admin"), "user", cell));
    }

    @Test
    void assess_expectDenyAndGot403_isOk() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        var cell = RbacCellResult.ok(403, 0, 0);
        assertEquals(AccessRuleSet.Assessment.OK,
                rs.assess(List.of("Admin"), "user", cell));
    }

    @Test
    void assess_noExpectation_noCall() {
        var rs = AccessRuleSet.empty();
        var cell = RbacCellResult.ok(200, 0, 0);
        assertEquals(AccessRuleSet.Assessment.NO_EXPECTATION,
                rs.assess(List.of("Users"), "user", cell));
    }

    @Test
    void assess_errorCell_isInconclusive() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        var cell = RbacCellResult.error("timeout", 0);
        assertEquals(AccessRuleSet.Assessment.INCONCLUSIVE,
                rs.assess(List.of("Admin"), "admin", cell));
    }

    @Test
    void assess_nullCell_noExpectation() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        assertEquals(AccessRuleSet.Assessment.NO_EXPECTATION,
                rs.assess(List.of("Admin"), "admin", null));
    }

    @Test
    void parse_multilineWithCommentsAndBlanks() {
        var rs = AccessRuleSet.parse("""
                # Admin rules
                Admin -> admin*

                # Public
                Public -> *
                invalid-line
                """);
        assertEquals(2, rs.rules().size());
    }

    @Test
    void parse_emptyOrNullReturnsEmpty() {
        assertTrue(AccessRuleSet.parse(null).isEmpty());
        assertTrue(AccessRuleSet.parse("").isEmpty());
        assertTrue(AccessRuleSet.parse("   \n  ").isEmpty());
    }

    @Test
    void rules_unmodifiable() {
        var rs = AccessRuleSet.parse("Admin -> admin");
        assertThrows(UnsupportedOperationException.class,
                () -> rs.rules().add(new AccessRule("Other", List.of("x"))));
    }

    @Test
    void constructorAcceptsNullList() {
        assertTrue(new AccessRuleSet(null).isEmpty());
    }

    @Test
    void assessmentHumanLabel_blankForNoExpectation() {
        assertEquals("", AccessRuleSet.Assessment.NO_EXPECTATION.humanLabel());
    }

    @Test
    void assessmentHumanLabel_formattedForRealValues() {
        assertEquals("OK", AccessRuleSet.Assessment.OK.humanLabel());
        assertEquals("Violation", AccessRuleSet.Assessment.VIOLATION.humanLabel());
        assertEquals("Inconclusive", AccessRuleSet.Assessment.INCONCLUSIVE.humanLabel());
    }
}
