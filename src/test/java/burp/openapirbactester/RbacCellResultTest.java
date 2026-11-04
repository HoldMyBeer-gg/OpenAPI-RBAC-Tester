package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RbacCellResultTest {

    @Test
    void ok_factorySetsStatusAndClearsError() {
        var cell = RbacCellResult.ok(200, 1234, 45);
        assertEquals(200, cell.statusCode());
        assertEquals(1234, cell.bodySize());
        assertEquals(45, cell.elapsedMs());
        assertNull(cell.errorMessage());
        assertFalse(cell.isError());
    }

    @Test
    void error_factorySetsNegativeStatusAndMessage() {
        var cell = RbacCellResult.error("timeout", 5000);
        assertEquals(-1, cell.statusCode());
        assertEquals(-1, cell.bodySize());
        assertEquals(5000, cell.elapsedMs());
        assertEquals("timeout", cell.errorMessage());
        assertTrue(cell.isError());
    }

    @Test
    void error_nullMessage_fallsBackToPlaceholder() {
        var cell = RbacCellResult.error(null, 0);
        assertEquals("unknown error", cell.errorMessage());
    }

    @Test
    void statusCategoryPredicates() {
        assertTrue(RbacCellResult.ok(200, 0, 0).is2xx());
        assertTrue(RbacCellResult.ok(299, 0, 0).is2xx());
        assertFalse(RbacCellResult.ok(300, 0, 0).is2xx());

        assertTrue(RbacCellResult.ok(301, 0, 0).is3xx());
        assertTrue(RbacCellResult.ok(399, 0, 0).is3xx());
        assertFalse(RbacCellResult.ok(400, 0, 0).is3xx());

        assertTrue(RbacCellResult.ok(401, 0, 0).isAuthDenied());
        assertTrue(RbacCellResult.ok(403, 0, 0).isAuthDenied());
        assertFalse(RbacCellResult.ok(404, 0, 0).isAuthDenied());
        assertFalse(RbacCellResult.ok(200, 0, 0).isAuthDenied());

        assertTrue(RbacCellResult.ok(404, 0, 0).isNotFound());
        assertFalse(RbacCellResult.ok(403, 0, 0).isNotFound());

        assertTrue(RbacCellResult.ok(500, 0, 0).is5xx());
        assertTrue(RbacCellResult.ok(599, 0, 0).is5xx());
        assertFalse(RbacCellResult.ok(600, 0, 0).is5xx());
        assertFalse(RbacCellResult.ok(499, 0, 0).is5xx());
    }

    @Test
    void shortLabel_numericForOk_errForError() {
        assertEquals("200", RbacCellResult.ok(200, 0, 0).shortLabel());
        assertEquals("404", RbacCellResult.ok(404, 0, 0).shortLabel());
        assertEquals("err", RbacCellResult.error("...", 0).shortLabel());
    }
}
