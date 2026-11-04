package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import static org.junit.jupiter.api.Assertions.*;

class RbacResultTableModelTest {

    private static ApiEndpoint ep(int i, String path) {
        return new ApiEndpoint(i, "https", "GET", "https://api.test.com", path, List.of(), "");
    }

    @Test
    void columnCount_includesDivergence() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon", "user", "admin"));
        // # Method Path + 3 identities + Divergence = 7
        assertEquals(7, model.getColumnCount());
    }

    @Test
    void columnNames_matchExpectedOrder() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon", "admin"));
        assertEquals("#", model.getColumnName(0));
        assertEquals("Method", model.getColumnName(1));
        assertEquals("Path", model.getColumnName(2));
        assertEquals("anon", model.getColumnName(3));
        assertEquals("admin", model.getColumnName(4));
        assertEquals("Divergence", model.getColumnName(5));
    }

    @Test
    void columnClasses_integerForIndex_divergenceForLast_cellInMiddle() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon"));
        assertEquals(Integer.class, model.getColumnClass(0));
        assertEquals(String.class, model.getColumnClass(1));
        assertEquals(String.class, model.getColumnClass(2));
        assertEquals(RbacCellResult.class, model.getColumnClass(3));
        assertEquals(DivergenceLevel.class, model.getColumnClass(4));
    }

    @Test
    void getValueAt_returnsEndpointFieldsForMetadataColumns() {
        var model = new RbacResultTableModel(
                List.of(ep(7, "/a")),
                List.of("anon"));
        assertEquals(7, model.getValueAt(0, 0));
        assertEquals("GET", model.getValueAt(0, 1));
        assertEquals("/a", model.getValueAt(0, 2));
    }

    @Test
    void getValueAt_pendingCell_returnsNull() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon"));
        assertNull(model.getValueAt(0, 3));
    }

    @Test
    void setCell_firesUpdateForCellAndDivergenceColumn() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon", "admin"));
        var events = new java.util.ArrayList<TableModelEvent>();
        model.addTableModelListener(events::add);
        model.setCell(0, 0, RbacCellResult.ok(200, 0, 0), null);
        // Expect 2 updates: identity column 3 and divergence column 5.
        assertEquals(2, events.size());
        assertEquals(3, events.get(0).getColumn());
        assertEquals(5, events.get(1).getColumn());
    }

    @Test
    void divergenceFor_healthyTieredRow() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/admin")),
                List.of("anon", "user", "admin"));
        model.setCell(0, 0, RbacCellResult.ok(401, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(403, 0, 0), null);
        model.setCell(0, 2, RbacCellResult.ok(200, 0, 0), null);
        assertEquals(DivergenceLevel.TIERED, model.divergenceFor(0));
    }

    @Test
    void divergenceFor_partialRow_isUnknown() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/x")),
                List.of("anon", "admin"));
        model.setCell(0, 0, RbacCellResult.ok(200, 0, 0), null);
        assertEquals(DivergenceLevel.UNKNOWN, model.divergenceFor(0));
    }

    @Test
    void getRawResponse_storedAndRetrievable() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon"));
        Object raw = new Object();
        model.setCell(0, 0, RbacCellResult.ok(200, 0, 0), raw);
        assertSame(raw, model.getRawResponse(0, 0));
    }

    @Test
    void divergenceHistogram_countsPerBucket() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a"), ep(2, "/b"), ep(3, "/c")),
                List.of("anon", "admin"));
        // row 0: 401 / 200 → TIERED
        model.setCell(0, 0, RbacCellResult.ok(401, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 0, 0), null);
        // row 1: 200 / 403 → DIVERGENT
        model.setCell(1, 0, RbacCellResult.ok(200, 0, 0), null);
        model.setCell(1, 1, RbacCellResult.ok(403, 0, 0), null);
        // row 2 left partial → UNKNOWN

        int[] histogram = model.divergenceHistogram();
        assertEquals(1, histogram[DivergenceLevel.TIERED.ordinal()]);
        assertEquals(1, histogram[DivergenceLevel.DIVERGENT.ordinal()]);
        assertEquals(1, histogram[DivergenceLevel.UNKNOWN.ordinal()]);
    }

    @Test
    void divergenceFor_objectScopedEndpoint_identicalCredentialedBodies_isHorizontal() {
        var idParam = new ApiEndpoint.ParameterInfo("id", "path", "1");
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}", List.of(idParam), "");
        var model = new RbacResultTableModel(List.of(ep),
                List.of("anon", "user", "admin"), List.of(false, true, true));
        model.setCell(0, 0, RbacCellResult.ok(401, 0, 0, "e"), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 9, 0, "same"), null);
        model.setCell(0, 2, RbacCellResult.ok(200, 9, 0, "same"), null);
        assertEquals(DivergenceLevel.HORIZONTAL, model.divergenceFor(0));
    }

    @Test
    void divergenceFor_templatedPathWithoutDeclaredParams_stillObjectScoped() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}", List.of(), "");
        var model = new RbacResultTableModel(List.of(ep), List.of("user", "admin"), List.of(true, true));
        model.setCell(0, 0, RbacCellResult.ok(200, 9, 0, "same"), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 9, 0, "same"), null);
        assertEquals(DivergenceLevel.HORIZONTAL, model.divergenceFor(0));
    }

    private static ApiEndpoint objectEp(int i, String path) {
        return new ApiEndpoint(i, "https", "GET", "https://api.test.com", path,
                List.of(new ApiEndpoint.ParameterInfo("id", "path", "1")), "");
    }

    @Test
    void peers_userAndAdminDifferElsewhere_soSharedObjectIsNotIdor() {
        var model = new RbacResultTableModel(List.of(ep(1, "/admin"), objectEp(2, "/users/{id}")),
                List.of("user", "admin"), List.of(true, true));
        model.setCell(0, 0, RbacCellResult.ok(403, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 5, 0, "cfg"), null);
        model.setCell(1, 0, RbacCellResult.ok(200, 9, 0, "same"), null);
        model.setCell(1, 1, RbacCellResult.ok(200, 9, 0, "same"), null);
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW, model.divergenceFor(1));
    }

    @Test
    void peers_twoUsersBehaveAlikeEverywhere_soSharedObjectIsIdor() {
        var model = new RbacResultTableModel(List.of(ep(1, "/admin"), objectEp(2, "/users/{id}")),
                List.of("userA", "userB", "admin"), List.of(true, true, true));
        model.setCell(0, 0, RbacCellResult.ok(403, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(403, 0, 0), null);
        model.setCell(0, 2, RbacCellResult.ok(200, 5, 0, "cfg"), null);
        model.setCell(1, 0, RbacCellResult.ok(200, 9, 0, "same"), null);
        model.setCell(1, 1, RbacCellResult.ok(200, 9, 0, "same"), null);
        model.setCell(1, 2, RbacCellResult.ok(200, 9, 0, "same"), null);
        assertEquals(DivergenceLevel.HORIZONTAL, model.divergenceFor(1));
    }

    @Test
    void peers_laterRowCanRevokePeerStatus_andOtherRowsReclassify() {
        var model = new RbacResultTableModel(List.of(ep(1, "/admin"), objectEp(2, "/users/{id}")),
                List.of("user", "admin"), List.of(true, true));
        model.setCell(1, 0, RbacCellResult.ok(200, 9, 0, "same"), null);
        model.setCell(1, 1, RbacCellResult.ok(200, 9, 0, "same"), null);
        assertEquals(DivergenceLevel.HORIZONTAL, model.divergenceFor(1), "no evidence of hierarchy yet");

        model.setCell(0, 0, RbacCellResult.ok(403, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 5, 0, "cfg"), null);
        assertEquals(DivergenceLevel.CONSISTENT_ALLOW, model.divergenceFor(1), "admin outranks user, not peers");
        assertEquals(1, model.divergenceHistogram()[DivergenceLevel.CONSISTENT_ALLOW.ordinal()]);
        assertEquals(0, model.divergenceHistogram()[DivergenceLevel.HORIZONTAL.ordinal()]);
    }

    @Test
    void divergenceFor_twoArgConstructor_treatsEveryIdentityAsCredentialed() {
        var idParam = new ApiEndpoint.ParameterInfo("id", "path", "1");
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}", List.of(idParam), "");
        var model = new RbacResultTableModel(List.of(ep), List.of("a", "b"));
        model.setCell(0, 0, RbacCellResult.ok(200, 9, 0, "same"), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 9, 0, "same"), null);
        assertEquals(DivergenceLevel.HORIZONTAL, model.divergenceFor(0));
    }

    @Test
    void identityNames_returnsCopy() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon", "admin"));
        var names = model.identityNames();
        names.clear();
        assertEquals(2, model.identityNames().size(), "mutation of returned list must not affect model");
    }

    @Test
    void endpointAt_returnsExpectedEndpoint() {
        var a = ep(1, "/a");
        var b = ep(2, "/b");
        var model = new RbacResultTableModel(List.of(a, b), List.of("anon"));
        assertSame(a, model.endpointAt(0));
        assertSame(b, model.endpointAt(1));
    }

    @Test
    void getCell_returnsPreviouslySetValue() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon"));
        var cell = RbacCellResult.ok(200, 0, 0);
        model.setCell(0, 0, cell, null);
        assertSame(cell, model.getCell(0, 0));
    }

    @Test
    void rowCount_matchesEndpoints() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a"), ep(2, "/b"), ep(3, "/c")),
                List.of("x"));
        assertEquals(3, model.getRowCount());
    }

    @Test
    void getValueAt_divergenceColumnReflectsClassification() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon", "admin"));
        model.setCell(0, 0, RbacCellResult.ok(403, 0, 0), null);
        model.setCell(0, 1, RbacCellResult.ok(200, 0, 0), null);
        // Cols: 0=# 1=Method 2=Path 3=anon 4=admin 5=Divergence
        assertEquals(DivergenceLevel.TIERED, model.getValueAt(0, 5));
    }

    @Test
    void manyListeners_allReceiveEvents() {
        var model = new RbacResultTableModel(
                List.of(ep(1, "/a")),
                List.of("anon"));
        AtomicInteger counter = new AtomicInteger(0);
        TableModelListener l1 = e -> counter.incrementAndGet();
        TableModelListener l2 = e -> counter.incrementAndGet();
        model.addTableModelListener(l1);
        model.addTableModelListener(l2);
        model.setCell(0, 0, RbacCellResult.ok(200, 0, 0), null);
        // 2 events × 2 listeners = 4 notifications
        assertEquals(4, counter.get());
    }
}
