package burp.openapirbactester;

import java.util.List;

/**
 * Tiny RFC 4180 CSV writer: double-quotes fields that contain commas, quotes,
 * or newlines, and doubles embedded quotes. No external dependency.
 */
public final class CsvWriter {

    private final StringBuilder out = new StringBuilder();

    public CsvWriter writeRow(List<String> cells) {
        boolean first = true;
        for (String cell : cells) {
            if (!first) out.append(',');
            out.append(quoteIfNeeded(cell));
            first = false;
        }
        out.append("\r\n");
        return this;
    }

    public String build() {
        return out.toString();
    }

    static String quoteIfNeeded(String raw) {
        if (raw == null) return "";
        boolean needsQuote = raw.indexOf(',') >= 0
                || raw.indexOf('"') >= 0
                || raw.indexOf('\n') >= 0
                || raw.indexOf('\r') >= 0;
        if (!needsQuote) return raw;
        StringBuilder sb = new StringBuilder(raw.length() + 4);
        sb.append('"');
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '"') sb.append('"').append('"');
            else sb.append(c);
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * Serialises an RBAC result matrix to CSV. Columns:
     * {@code #, Method, Path, <identity>…, Divergence, Divergence explanation, Assessment}.
     * Divergence and Assessment use human-readable labels (not raw enum names), and the
     * explanation column makes each row self-documenting for non-developer stakeholders
     * reading the export.
     */
    public static String fromMatrix(RbacResultTableModel model, AccessRuleSet rules) {
        CsvWriter w = new CsvWriter();
        List<String> header = new java.util.ArrayList<>();
        header.add("#");
        header.add("Method");
        header.add("Path");
        header.addAll(model.identityNames());
        header.add("Divergence");
        header.add("Divergence explanation");
        header.add("Assessment");
        w.writeRow(header);
        for (int r = 0; r < model.getRowCount(); r++) {
            List<String> row = new java.util.ArrayList<>();
            ApiEndpoint ep = model.endpointAt(r);
            row.add(Integer.toString(ep.getIndex()));
            row.add(ep.getMethod());
            row.add(ep.getPath());
            AccessRuleSet.Assessment worst = AccessRuleSet.Assessment.NO_EXPECTATION;
            for (int c = 0; c < model.identityNames().size(); c++) {
                RbacCellResult cell = model.getCell(r, c);
                row.add(cell == null ? "" : cell.shortLabel());
                AccessRuleSet.Assessment a = rules.assess(ep.getTags(),
                        model.identityNames().get(c), cell);
                if (a == AccessRuleSet.Assessment.VIOLATION) worst = a;
                else if (worst == AccessRuleSet.Assessment.NO_EXPECTATION && a != AccessRuleSet.Assessment.NO_EXPECTATION) {
                    worst = a;
                }
            }
            DivergenceLevel level = model.divergenceFor(r);
            row.add(level.humanLabel());
            row.add(level.explanation());
            row.add(worst.humanLabel());
            w.writeRow(row);
        }
        return w.build();
    }
}
