package burp.openapibifrost;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link EndpointTableModel}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class EndpointTableModelTest {

    private EndpointTableModel model;
    private List<ApiEndpoint> endpoints;

    @BeforeEach
    void setUp() {
        model = new EndpointTableModel();
        endpoints = List.of(
                new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "List"),
                new ApiEndpoint(2, "https", "POST", "https://api.test.com", "/users", List.of(), "Create")
        );
    }

    @Test
    void setEndpoints_updatesTable() {
        model.setEndpoints(endpoints);
        assertEquals(2, model.getRowCount());
        assertEquals(7, model.getColumnCount());
        assertEquals("#", model.getColumnName(0));
        assertEquals("GET", model.getValueAt(0, 2));
    }

    @Test
    void setEndpoints_null_clearsTable() {
        model.setEndpoints(endpoints);
        model.setEndpoints(null);
        assertEquals(0, model.getRowCount());
    }

    @Test
    void setFilter_matching_reducesRows() {
        model.setEndpoints(endpoints);
        model.setFilter("POST");
        assertEquals(1, model.getFilterHitCount());
        assertEquals("POST", model.getValueAt(0, 2));
    }

    @Test
    void setFilter_sameRegexTwice_skipsRecompileAndRefire() {
        model.setEndpoints(endpoints);
        model.setFilter("POST");
        var events = new java.util.concurrent.atomic.AtomicInteger();
        model.addTableModelListener(e -> events.incrementAndGet());

        model.setFilter("POST");

        assertEquals(0, events.get(), "identical filter text should be a no-op");
        assertEquals(1, model.getFilterHitCount());
    }

    @Test
    void setFilter_changedRegex_refires() {
        model.setEndpoints(endpoints);
        model.setFilter("POST");
        var events = new java.util.concurrent.atomic.AtomicInteger();
        model.addTableModelListener(e -> events.incrementAndGet());

        model.setFilter("GET");

        assertEquals(1, events.get());
        assertEquals("GET", model.getValueAt(0, 2));
    }

    @Test
    void setFilter_invalidRegex_ignored() {
        model.setEndpoints(endpoints);
        model.setFilter("[invalid");
        assertEquals(2, model.getFilterHitCount());
    }

    @Test
    void getEndpointAt_validIndex_returnsEndpoint() {
        model.setEndpoints(endpoints);
        var ep = model.getEndpointAt(0);
        assertNotNull(ep);
        assertEquals("/users", ep.getPath());
    }

    @Test
    void getEndpointAt_invalidIndex_returnsNull() {
        model.setEndpoints(endpoints);
        assertNull(model.getEndpointAt(-1));
        assertNull(model.getEndpointAt(99));
    }

    @Test
    void getSelectedEndpoints_returnsList() {
        model.setEndpoints(endpoints);
        var selected = model.getSelectedEndpoints(new int[]{0, 1});
        assertEquals(2, selected.size());
    }

    @Test
    void formatParams_multipleTypes() {
        var params = List.of(
                new ApiEndpoint.ParameterInfo("id", "path", "1"),
                new ApiEndpoint.ParameterInfo("limit", "query", "10"),
                new ApiEndpoint.ParameterInfo("token", "header", "xyz")
        );
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}", params, "");
        model.setEndpoints(List.of(ep));
        String paramStr = (String) model.getValueAt(0, 5);
        assertTrue(paramStr.contains("PATH:id"));
        assertTrue(paramStr.contains("QUERY:limit"));
        assertTrue(paramStr.contains("HEADER:token"));
    }

    @Test
    void formatParams_emptyList() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        model.setEndpoints(List.of(ep));
        String paramStr = (String) model.getValueAt(0, 5);
        assertEquals("", paramStr);
    }

    @Test
    void getValueAt_allColumns() {
        model.setEndpoints(endpoints);
        assertEquals(1, model.getValueAt(0, 0)); // index
        assertEquals("https", model.getValueAt(0, 1)); // scheme
        assertEquals("GET", model.getValueAt(0, 2)); // method
        assertEquals("https://api.test.com", model.getValueAt(0, 3)); // server
        assertEquals("/users", model.getValueAt(0, 4)); // path
        assertNotNull(model.getValueAt(0, 5)); // parameters
        assertEquals("List", model.getValueAt(0, 6)); // description
    }

    @Test
    void getValueAt_invalidColumn_returnsEmpty() {
        model.setEndpoints(endpoints);
        assertEquals("", model.getValueAt(0, 99));
    }

    @Test
    void setFilter_emptyString_showsAll() {
        model.setEndpoints(endpoints);
        model.setFilter("");
        assertEquals(2, model.getFilterHitCount());
    }

    @Test
    void setFilter_null_showsAll() {
        model.setEndpoints(endpoints);
        model.setFilter(null);
        assertEquals(2, model.getFilterHitCount());
    }

    @Test
    void setFilter_noMatch_returnsZero() {
        model.setEndpoints(endpoints);
        model.setFilter("NOTFOUND");
        assertEquals(0, model.getFilterHitCount());
    }

    @Test
    void setFilter_caseInsensitiveRegex() {
        model.setEndpoints(endpoints);
        model.setFilter("(?i)post");
        assertEquals(1, model.getFilterHitCount());
    }

    @Test
    void getSelectedEndpoints_emptyArray() {
        model.setEndpoints(endpoints);
        var selected = model.getSelectedEndpoints(new int[]{});
        assertEquals(0, selected.size());
    }

    @Test
    void getSelectedEndpoints_invalidIndices() {
        model.setEndpoints(endpoints);
        var selected = model.getSelectedEndpoints(new int[]{-1, 99});
        assertEquals(0, selected.size());
    }

    @Test
    void getValueAt_afterFiltering_returnsCorrectEndpoint() {
        model.setEndpoints(endpoints);
        model.setFilter("POST");
        // After filtering, row 0 should be the POST endpoint
        assertEquals("POST", model.getValueAt(0, 2));
        assertEquals("/users", model.getValueAt(0, 4));
    }

    @Test
    void setFilter_matchesServerUrl() {
        model.setEndpoints(endpoints);
        model.setFilter("api.test.com");
        assertEquals(2, model.getFilterHitCount());
    }

    @Test
    void setFilter_matchesPath() {
        model.setEndpoints(endpoints);
        model.setFilter("/users");
        assertEquals(2, model.getFilterHitCount());
    }
}
