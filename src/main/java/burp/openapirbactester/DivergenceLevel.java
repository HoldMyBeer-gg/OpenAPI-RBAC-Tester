package burp.openapirbactester;

import java.util.List;

/**
 * Classifies the across-identity response pattern for a single endpoint into a short
 * label the UI can colour and the human can eyeball. Identity order in the cells list
 * represents priority ascending — index 0 is the least-privileged identity (e.g.
 * anonymous), last index the most-privileged (e.g. admin).
 */
public enum DivergenceLevel {

    /** Not every cell has completed yet. */
    UNKNOWN,

    /** All network errors; nothing to compare. */
    ALL_ERRORED,

    /** Every identity got a 2xx — endpoint is effectively public (or tiering is broken open). */
    CONSISTENT_ALLOW,

    /** Every identity got denied (4xx/5xx) — consistent rejection. */
    CONSISTENT_DENY,

    /** Allow outcomes form a monotonic suffix — lower-priority identities denied, higher-priority allowed. Healthy. */
    TIERED,

    /** Non-monotonic: a lower-priority identity got a 2xx that a higher-priority did not (or similar). */
    DIVERGENT;

    /** Short human-readable label for UI columns and CSV output. */
    public String humanLabel() {
        return switch (this) {
            case UNKNOWN -> "Unknown";
            case ALL_ERRORED -> "All errored";
            case CONSISTENT_ALLOW -> "Consistent allow";
            case CONSISTENT_DENY -> "Consistent deny";
            case TIERED -> "Tiered";
            case DIVERGENT -> "Divergent";
        };
    }

    /**
     * Longer single-sentence explanation suitable for tooltips and the CSV's
     * explanation column. Written so a reader unfamiliar with the tool can make
     * sense of a row without needing to consult the README.
     */
    public String explanation() {
        return switch (this) {
            case UNKNOWN ->
                    "Row is not fully computed yet (or the run was cancelled).";
            case ALL_ERRORED ->
                    "Every identity's request failed at the network layer — can't judge access.";
            case CONSISTENT_ALLOW ->
                    "Every identity got a 2xx — endpoint is effectively public or tiering is broken open.";
            case CONSISTENT_DENY ->
                    "Every identity hit the same wall (same status category) — consistent rejection.";
            case TIERED ->
                    "Higher-privilege identities reached further through the server's stack (auth → resource → success) than lower-privilege ones — healthy role separation.";
            case DIVERGENT ->
                    "A lower-privilege identity got further through the server's stack than a higher-privilege one — possible authorization inversion.";
        };
    }

    /**
     * Classifies a row of cells in identity-priority order.
     * <p>
     * Uses a "stack depth" model to distinguish how far each request got through the
     * server's processing pipeline, rather than a binary allow/deny split:
     * <ul>
     *   <li>Depth 2 — 2xx/3xx: request passed auth <em>and</em> resource resolved</li>
     *   <li>Depth 1 — 404:    request passed auth, resource missing (common when we
     *                          substitute a fake UUID into a path param)</li>
     *   <li>Depth 0 — 401/403/400/422/5xx: blocked at auth, validation, or server error</li>
     * </ul>
     * This lets the classifier flag {@code [403, 403, 404]} as {@link #TIERED} (SuperAdmin
     * passed auth that the others didn't, even though no one got a 2xx) instead of
     * burying it as {@link #CONSISTENT_DENY}.
     *
     * @param cells cells for one endpoint, ordered least-privileged first. {@code null}
     *              entries mean "not yet computed" — the row is considered {@link #UNKNOWN}.
     */
    public static DivergenceLevel classify(List<RbacCellResult> cells) {
        if (cells == null || cells.isEmpty()) return UNKNOWN;
        for (RbacCellResult c : cells) {
            if (c == null) return UNKNOWN;
        }

        long errorCount = cells.stream().filter(RbacCellResult::isError).count();
        if (errorCount == cells.size()) return ALL_ERRORED;

        // Map each non-error cell to a depth value; skip cells that errored.
        int[] depths = new int[cells.size()];
        int validCount = 0;
        for (int i = 0; i < cells.size(); i++) {
            RbacCellResult c = cells.get(i);
            if (c.isError()) {
                depths[i] = Integer.MIN_VALUE;
                continue;
            }
            depths[i] = depthOf(c);
            validCount++;
        }
        if (validCount == 0) return ALL_ERRORED;

        // "All same depth" means all identities had the same stack outcome.
        int first = firstValidDepth(depths);
        boolean allSame = true;
        for (int d : depths) {
            if (d == Integer.MIN_VALUE) continue;
            if (d != first) { allSame = false; break; }
        }
        if (allSame) {
            return first == 2 ? CONSISTENT_ALLOW : CONSISTENT_DENY;
        }

        // Not all the same — walk left to right, confirming monotonic non-decreasing depth.
        int previous = Integer.MIN_VALUE;
        for (int d : depths) {
            if (d == Integer.MIN_VALUE) continue;
            if (previous != Integer.MIN_VALUE && d < previous) {
                return DIVERGENT;
            }
            previous = d;
        }
        return TIERED;
    }

    private static int firstValidDepth(int[] depths) {
        for (int d : depths) {
            if (d != Integer.MIN_VALUE) return d;
        }
        return 0;
    }

    private static int depthOf(RbacCellResult c) {
        if (c.is2xx() || c.is3xx()) return 2;
        if (c.isNotFound()) return 1;
        return 0;
    }
}
