package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AccessRuleTest {

    @Test
    void constructor_blankTag_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new AccessRule("", List.of("admin")));
        assertThrows(IllegalArgumentException.class,
                () -> new AccessRule(null, List.of("admin")));
        assertThrows(IllegalArgumentException.class,
                () -> new AccessRule("   ", List.of("admin")));
    }

    @Test
    void constructor_emptyAllowedList_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new AccessRule("Admin", List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new AccessRule("Admin", null));
    }

    @Test
    void appliesTo_matchesExactTag() {
        AccessRule rule = new AccessRule("Admin", List.of("admin"));
        assertTrue(rule.appliesTo(List.of("Admin")));
        assertFalse(rule.appliesTo(List.of("Users")));
    }

    @Test
    void appliesTo_caseInsensitive() {
        AccessRule rule = new AccessRule("admin", List.of("admin"));
        assertTrue(rule.appliesTo(List.of("ADMIN")));
        assertTrue(rule.appliesTo(List.of("Admin")));
    }

    @Test
    void appliesTo_globMatch() {
        AccessRule rule = new AccessRule("admin*", List.of("x"));
        assertTrue(rule.appliesTo(List.of("admin")));
        assertTrue(rule.appliesTo(List.of("admin-only")));
        assertTrue(rule.appliesTo(List.of("adminstuff")));
        assertFalse(rule.appliesTo(List.of("user")));
    }

    @Test
    void appliesTo_questionMarkWildcard() {
        AccessRule rule = new AccessRule("v?", List.of("x"));
        assertTrue(rule.appliesTo(List.of("v1")));
        assertTrue(rule.appliesTo(List.of("v2")));
        assertFalse(rule.appliesTo(List.of("v10")));
    }

    @Test
    void appliesTo_anyTagMatches() {
        AccessRule rule = new AccessRule("Admin", List.of("x"));
        assertTrue(rule.appliesTo(List.of("Users", "Admin", "Public")));
    }

    @Test
    void appliesTo_noTagsAndNonTrivialPattern_returnsFalse() {
        AccessRule rule = new AccessRule("Admin", List.of("x"));
        assertFalse(rule.appliesTo(List.of()));
        assertFalse(rule.appliesTo(null));
    }

    @Test
    void appliesTo_starMatchesEvenEmptyTagList() {
        AccessRule rule = new AccessRule("*", List.of("x"));
        // Pattern * against "" (no tags) matches.
        assertTrue(rule.appliesTo(List.of()));
    }

    @Test
    void allows_exactMatch() {
        AccessRule rule = new AccessRule("admin", List.of("admin"));
        assertTrue(rule.allows("admin"));
        assertFalse(rule.allows("user"));
    }

    @Test
    void allows_globMatch() {
        AccessRule rule = new AccessRule("Admin", List.of("admin*"));
        assertTrue(rule.allows("admin"));
        assertTrue(rule.allows("admin-jwt"));
        assertFalse(rule.allows("user-jwt"));
    }

    @Test
    void allows_multiplePatterns() {
        AccessRule rule = new AccessRule("Admin", List.of("admin", "service-*"));
        assertTrue(rule.allows("admin"));
        assertTrue(rule.allows("service-bot"));
        assertFalse(rule.allows("user"));
    }

    @Test
    void allows_nullIdentity_treatedAsEmpty() {
        AccessRule rule = new AccessRule("Admin", List.of("*"));
        assertTrue(rule.allows(null));
    }

    @Test
    void parseLine_simpleArrowForm() {
        AccessRule rule = AccessRule.parseLine("Admin -> admin");
        assertNotNull(rule);
        assertEquals("Admin", rule.tagPattern());
        assertEquals(List.of("admin"), rule.allowedIdentityPatterns());
    }

    @Test
    void parseLine_stripsTagPrefix() {
        AccessRule rule = AccessRule.parseLine("tag:Admin -> admin");
        assertEquals("Admin", rule.tagPattern());
    }

    @Test
    void parseLine_multipleAllowed() {
        AccessRule rule = AccessRule.parseLine("Admin -> admin, service-*, root");
        assertEquals(List.of("admin", "service-*", "root"), rule.allowedIdentityPatterns());
    }

    @Test
    void parseLine_blanksAndCommentsReturnNull() {
        assertNull(AccessRule.parseLine(""));
        assertNull(AccessRule.parseLine("   "));
        assertNull(AccessRule.parseLine(null));
        assertNull(AccessRule.parseLine("# this is a comment"));
        assertNull(AccessRule.parseLine("  # leading whitespace comment"));
    }

    @Test
    void parseLine_missingArrowReturnsNull() {
        assertNull(AccessRule.parseLine("Admin admin"));
    }

    @Test
    void parseLine_emptySidesReturnNull() {
        assertNull(AccessRule.parseLine("-> admin"));
        assertNull(AccessRule.parseLine("Admin ->"));
        assertNull(AccessRule.parseLine("-> "));
        assertNull(AccessRule.parseLine("tag: -> admin"));
    }

    @Test
    void parseLine_allowedListWithEmptyEntries() {
        AccessRule rule = AccessRule.parseLine("Admin -> admin, ,  ,root");
        assertEquals(List.of("admin", "root"), rule.allowedIdentityPatterns());
    }

    @Test
    void globToRegex_escapesRegexSpecials() {
        // Pattern containing regex metacharacters should still work literally.
        assertTrue(AccessRule.matchesGlob("a.b", "a.b"));
        assertFalse(AccessRule.matchesGlob("a.b", "axb"), ". must be literal, not any char");
        assertTrue(AccessRule.matchesGlob("(group)", "(group)"));
        assertTrue(AccessRule.matchesGlob("a[b]c", "a[b]c"));
    }

    @Test
    void allowedIdentityPatterns_unmodifiable() {
        AccessRule rule = new AccessRule("x", List.of("a", "b"));
        assertThrows(UnsupportedOperationException.class,
                () -> rule.allowedIdentityPatterns().add("c"));
    }
}
