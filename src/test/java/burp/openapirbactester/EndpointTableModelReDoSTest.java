package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Ensures filter regex length limit mitigates ReDoS. Content is not sanitized for testing.
 */
class EndpointTableModelReDoSTest {

    @Test
    void setFilter_longRegex_ignored() {
        var model = new EndpointTableModel();
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/x", List.of(), "");
        model.setEndpoints(List.of(ep));
        StringBuilder longRegex = new StringBuilder();
        for (int i = 0; i < 600; i++) {
            longRegex.append("a");
        }
        model.setFilter(longRegex.toString());
        assertEquals(1, model.getFilterHitCount());
    }
}
