package burp.openapirbactester;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A collection of {@link AccessRule}s applied in order. Provides a single entry
 * point for "given this endpoint and this identity, what result should I expect
 * and did the observed status agree?"
 */
public final class AccessRuleSet {

    public enum Expectation {
        /** No rule applied — no opinion. */
        UNKNOWN,
        /** Rules say the identity should be allowed; a 4xx/5xx would be a violation. */
        EXPECT_ALLOW,
        /** Rules say the identity should be denied; a 2xx would be a violation. */
        EXPECT_DENY
    }

    /** Combined label: whether the observed cell agreed with the expectation. */
    public enum Assessment {
        NO_EXPECTATION,
        OK,
        VIOLATION,
        /** Cell errored; can't judge. */
        INCONCLUSIVE;

        /** Short human-readable label for CSV/UI. Returns "" for NO_EXPECTATION. */
        public String humanLabel() {
            return switch (this) {
                case NO_EXPECTATION -> "";
                case OK -> "OK";
                case VIOLATION -> "Violation";
                case INCONCLUSIVE -> "Inconclusive";
            };
        }
    }

    private final List<AccessRule> rules;

    public AccessRuleSet(List<AccessRule> rules) {
        this.rules = rules != null ? List.copyOf(rules) : List.of();
    }

    public static AccessRuleSet empty() {
        return new AccessRuleSet(List.of());
    }

    public static AccessRuleSet parse(String rawText) {
        if (rawText == null || rawText.isBlank()) return empty();
        List<AccessRule> parsed = new ArrayList<>();
        for (String line : rawText.split("\\r?\\n")) {
            AccessRule rule = AccessRule.parseLine(line);
            if (rule != null) parsed.add(rule);
        }
        return new AccessRuleSet(parsed);
    }

    public List<AccessRule> rules() {
        return Collections.unmodifiableList(rules);
    }

    public boolean isEmpty() {
        return rules.isEmpty();
    }

    /**
     * Computes the expectation for one (endpoint, identity) pair. Only rules whose
     * {@link AccessRule#appliesTo(List)} returns true contribute; across those:
     * if any rule allows the identity, we expect ALLOW, otherwise DENY.
     */
    public Expectation expectationFor(List<String> endpointTags, String identityName) {
        boolean anyApplied = false;
        boolean anyAllowed = false;
        for (AccessRule rule : rules) {
            if (!rule.appliesTo(endpointTags)) continue;
            anyApplied = true;
            if (rule.allows(identityName)) {
                anyAllowed = true;
            }
        }
        if (!anyApplied) return Expectation.UNKNOWN;
        return anyAllowed ? Expectation.EXPECT_ALLOW : Expectation.EXPECT_DENY;
    }

    /** Compares an expectation against an observed cell. */
    public Assessment assess(List<String> endpointTags, String identityName, RbacCellResult cell) {
        if (cell == null) return Assessment.NO_EXPECTATION;
        if (cell.isError()) return Assessment.INCONCLUSIVE;
        Expectation expectation = expectationFor(endpointTags, identityName);
        return switch (expectation) {
            case UNKNOWN -> Assessment.NO_EXPECTATION;
            case EXPECT_ALLOW -> cell.is2xx() ? Assessment.OK : Assessment.VIOLATION;
            case EXPECT_DENY -> cell.is2xx() ? Assessment.VIOLATION : Assessment.OK;
        };
    }
}
