package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CsvWriterTest {

    @Test
    void writeRow_simpleFields_noQuoting() {
        String csv = new CsvWriter()
                .writeRow(List.of("a", "b", "c"))
                .build();
        assertEquals("a,b,c\r\n", csv);
    }

    @Test
    void quoteIfNeeded_commaRequiresQuote() {
        assertEquals("\"a,b\"", CsvWriter.quoteIfNeeded("a,b"));
    }

    @Test
    void quoteIfNeeded_doubleQuoteDoubled() {
        assertEquals("\"say \"\"hi\"\"\"", CsvWriter.quoteIfNeeded("say \"hi\""));
    }

    @Test
    void quoteIfNeeded_newlineQuoted() {
        assertEquals("\"a\nb\"", CsvWriter.quoteIfNeeded("a\nb"));
        assertEquals("\"a\rb\"", CsvWriter.quoteIfNeeded("a\rb"));
    }

    @Test
    void quoteIfNeeded_simpleValueLeftAlone() {
        assertEquals("hello", CsvWriter.quoteIfNeeded("hello"));
    }

    @Test
    void quoteIfNeeded_nullReturnsEmpty() {
        assertEquals("", CsvWriter.quoteIfNeeded(null));
    }

    @Test
    void writeRow_multipleRowsConcatenated() {
        String csv = new CsvWriter()
                .writeRow(List.of("h1", "h2"))
                .writeRow(List.of("v1", "v2"))
                .build();
        assertEquals("h1,h2\r\nv1,v2\r\n", csv);
    }

    @Test
    void writeRow_nullCellsProduceEmpty() {
        String csv = new CsvWriter()
                .writeRow(java.util.Arrays.asList("a", null, "c"))
                .build();
        assertEquals("a,,c\r\n", csv);
    }

    @Test
    void fromMatrix_emptyModelProducesHeaderOnly() {
        var model = new RbacResultTableModel(List.of(), List.of("anon", "admin"));
        String csv = CsvWriter.fromMatrix(model, AccessRuleSet.empty());
        assertEquals("#,Method,Path,anon,admin,Divergence,Divergence explanation,Assessment\r\n", csv);
    }

    @Test
    void fromMatrix_populatedGrid_producesExpectedRow() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/admin",
                List.of(), "", List.of(), List.of("Admin"));
        var model = new RbacResultTableModel(List.of(ep), List.of("anon", "admin"));
        model.setCell(0, 0, RbacCellResult.ok(401, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 0, 0), null);

        var rules = AccessRuleSet.parse("Admin -> admin");
        String csv = CsvWriter.fromMatrix(model, rules);
        String[] lines = csv.split("\r\n");
        assertEquals("#,Method,Path,anon,admin,Divergence,Divergence explanation,Assessment", lines[0]);
        // Row contains: index, method, path, status, status, "Tiered", quoted explanation, "OK".
        assertTrue(lines[1].startsWith("1,GET,/admin,401,200,Tiered,"));
        assertTrue(lines[1].endsWith(",OK"));
        assertTrue(lines[1].contains("role separation"), "explanation should be present");
    }

    @Test
    void fromMatrix_violationSurfacesInAssessment() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/admin",
                List.of(), "", List.of(), List.of("Admin"));
        var model = new RbacResultTableModel(List.of(ep), List.of("user", "admin"));
        // user got 200 on an Admin-tagged endpoint, admin got 200 — user violates rule.
        model.setCell(0, 0, RbacCellResult.ok(200, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 0, 0), null);

        var rules = AccessRuleSet.parse("Admin -> admin");
        String csv = CsvWriter.fromMatrix(model, rules);
        assertTrue(csv.contains(",Violation\r\n"), "user's 200 on admin-tagged endpoint should mark Violation");
    }

    @Test
    void fromMatrix_specialCharsInPathQuotedInCsv() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com",
                "/users/{id},comma", List.of(), "", List.of(), List.of());
        var model = new RbacResultTableModel(List.of(ep), List.of("anon"));
        model.setCell(0, 0, RbacCellResult.ok(200, 0, 0), null);
        String csv = CsvWriter.fromMatrix(model, AccessRuleSet.empty());
        assertTrue(csv.contains("\"/users/{id},comma\""),
                "path with comma should be quoted");
    }

    @Test
    void fromMatrix_pendingCellsRenderAsEmpty() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/x",
                List.of(), "", List.of(), List.of());
        var model = new RbacResultTableModel(List.of(ep), List.of("anon", "admin"));
        model.setCell(0, 0, RbacCellResult.ok(200, 0, 0), null);
        // col 1 left pending
        String csv = CsvWriter.fromMatrix(model, AccessRuleSet.empty());
        assertTrue(csv.contains("1,GET,/x,200,,Unknown,"),
                "pending cell should render as empty field and divergence as Unknown, got: " + csv);
        // Last column (Assessment) should be empty when no rule applies.
        String[] lines = csv.split("\r\n");
        assertTrue(lines[1].endsWith(","),
                "Assessment should be blank when no rule applies, row was: " + lines[1]);
    }
}
