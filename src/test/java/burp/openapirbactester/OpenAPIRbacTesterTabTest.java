package burp.openapirbactester;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.RawEditor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Headless tests for the Montoya wiring inside {@link OpenAPIRbacTesterTab}. Swing panels
 * build fine without a display; only top-level windows need one, so the RBAC dialog
 * itself stays out of these tests.
 */
class OpenAPIRbacTesterTabTest {

    private static final String SPEC_URL = "https://api.example.test/openapi.json";

    private MontoyaApi api;
    private Http http;
    private MontoyaObjectFactory factory;
    private OpenAPIRbacTesterTab tab;

    @BeforeEach
    void setUp() {
        api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        http = mock(Http.class);
        when(api.http()).thenReturn(http);

        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(api.userInterface().createHttpRequestEditor()).thenReturn(requestEditor);

        RawEditor rawEditor = mock(RawEditor.class);
        when(rawEditor.uiComponent()).thenReturn(new JPanel());
        ByteArray empty = mock(ByteArray.class);
        when(empty.getBytes()).thenReturn(new byte[0]);
        when(rawEditor.getContents()).thenReturn(empty);
        when(api.userInterface().createRawEditor()).thenReturn(rawEditor);

        // Montoya's static factories (HttpRequest.httpRequestFromUrl, RequestOptions.requestOptions)
        // route through this locator, which Burp populates at load time.
        factory = mock(MontoyaObjectFactory.class);
        ObjectFactoryLocator.FACTORY = factory;

        tab = new OpenAPIRbacTesterTab(api, new IdentityStore(new InMemoryPrefs()));
    }

    @AfterEach
    void tearDown() {
        tab.unload();
        ObjectFactoryLocator.FACTORY = null;
    }

    @Test
    void loadFromUrl_sendsWithUpstreamTlsVerification() {
        HttpRequest req = mock(HttpRequest.class);
        when(factory.httpRequestFromUrl(SPEC_URL)).thenReturn(req);

        RequestOptions base = mock(RequestOptions.class);
        RequestOptions verified = mock(RequestOptions.class);
        when(factory.requestOptions()).thenReturn(base);
        when(base.withUpstreamTLSVerification()).thenReturn(verified);

        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{}".getBytes(StandardCharsets.UTF_8));
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.body()).thenReturn(body);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(rr);

        tab.loadFromUrl(SPEC_URL);

        verify(http).sendRequest(req, verified);
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void loadFromUrl_https_withVerifyTlsUnticked_sendsWithoutTlsOptions() {
        javax.swing.JCheckBox verify = findCheckBox(tab, "Verify TLS");
        assertTrue(verify != null, "Verify TLS checkbox should be on the tab");
        assertTrue(verify.isSelected(), "verification is on by default");
        verify.setSelected(false);

        HttpRequest req = mock(HttpRequest.class);
        when(factory.httpRequestFromUrl(SPEC_URL)).thenReturn(req);
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{}".getBytes(StandardCharsets.UTF_8));
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.body()).thenReturn(body);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(req)).thenReturn(rr);

        tab.loadFromUrl(SPEC_URL);

        verify(http).sendRequest(req);
        verify(http, never()).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
    }

    @Test
    void loadFromUrl_noResponse_overHttpsWithVerification_pointsAtTheCheckbox() throws Exception {
        HttpRequest req = mock(HttpRequest.class);
        when(factory.httpRequestFromUrl(SPEC_URL)).thenReturn(req);
        RequestOptions base = mock(RequestOptions.class);
        when(factory.requestOptions()).thenReturn(base);
        when(base.withUpstreamTLSVerification()).thenReturn(base);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(null);
        when(http.sendRequest(req, base)).thenReturn(rr);
        when(api.burpSuite().exportProjectOptionsAsJson(any(String[].class))).thenReturn("{}");

        tab.loadFromUrl(SPEC_URL);
        javax.swing.SwingUtilities.invokeAndWait(() -> { });

        String status = tab.statusText();
        assertTrue(status.contains("No response"), status);
        assertTrue(status.contains("Verify TLS"), "should tell the user how to get past a self-signed cert: " + status);
    }

    private static javax.swing.JCheckBox findCheckBox(java.awt.Container root, String text) {
        for (java.awt.Component c : root.getComponents()) {
            if (c instanceof javax.swing.JCheckBox b && text.equals(b.getText())) return b;
            if (c instanceof java.awt.Container inner) {
                javax.swing.JCheckBox found = findCheckBox(inner, text);
                if (found != null) return found;
            }
        }
        return null;
    }

    @Test
    void loadFromUrl_plainHttp_sendsWithoutTlsOptions() {
        String url = "http://127.0.0.1:8099/openapi.json";
        HttpRequest req = mock(HttpRequest.class);
        when(factory.httpRequestFromUrl(url)).thenReturn(req);

        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{}".getBytes(StandardCharsets.UTF_8));
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.body()).thenReturn(body);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(req)).thenReturn(rr);

        tab.loadFromUrl(url);

        verify(http).sendRequest(req);
        verify(http, never()).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
        verify(factory, never()).requestOptions();
    }

    @Test
    void loadFromUrl_noResponse_withSocksEnabled_namesTheProxyInStatus() throws Exception {
        String url = "http://127.0.0.1:8099/openapi.json";
        HttpRequest req = mock(HttpRequest.class);
        when(factory.httpRequestFromUrl(url)).thenReturn(req);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(null);
        when(http.sendRequest(req)).thenReturn(rr);
        when(api.burpSuite().exportProjectOptionsAsJson(any(String[].class))).thenReturn("""
                {"project_options":{"connections":{
                  "socks_proxy":{"host":"127.0.0.1","port":9119,"use_proxy":true,"use_user_options":false},
                  "upstream_proxy":{"servers":[],"use_user_options":false}}}}""");

        tab.loadFromUrl(url);
        javax.swing.SwingUtilities.invokeAndWait(() -> { }); // flush the status update

        String status = tab.statusText();
        assertTrue(status.contains("No response"), status);
        assertTrue(status.contains("SOCKS proxy at 127.0.0.1:9119"), status);
    }

    @Test
    void compareButton_isVisibleOnTheTab_andActsOnSelection() {
        javax.swing.JButton compare = findButton(tab, "Compare across identities…");
        assertTrue(compare != null, "Compare button should be on the tab, not only in the context menu");

        compare.doClick();

        assertTrue(tab.statusText().contains("Select one or more endpoints"), tab.statusText());
    }

    @Test
    void sendButtons_areVisibleOnTheTab() {
        assertTrue(findButton(tab, "Send to Repeater") != null);
        assertTrue(findButton(tab, "Send to Intruder") != null);
    }

    private static javax.swing.JButton findButton(java.awt.Container root, String text) {
        for (java.awt.Component c : root.getComponents()) {
            if (c instanceof javax.swing.JButton b && text.equals(b.getText())) return b;
            if (c instanceof java.awt.Container inner) {
                javax.swing.JButton found = findButton(inner, text);
                if (found != null) return found;
            }
        }
        return null;
    }

    @Test
    void unload_abortsTrackedComparisonRuns() {
        OpenAPIRbacTesterTab.AbortableRun run = mock(OpenAPIRbacTesterTab.AbortableRun.class);
        tab.trackRun(run);

        tab.unload();

        verify(run).abort();
    }

    @Test
    void unload_skipsRunsThatAlreadyFinished() {
        OpenAPIRbacTesterTab.AbortableRun run = mock(OpenAPIRbacTesterTab.AbortableRun.class);
        tab.trackRun(run);
        tab.untrackRun(run);

        tab.unload();

        verify(run, never()).abort();
    }

    /** In-memory stand-in for Montoya preferences. */
    static final class InMemoryPrefs implements IdentityStore.PrefsBackend {
        private final Map<String, String> map = new HashMap<>();
        @Override public String get(String key) { return map.get(key); }
        @Override public void put(String key, String value) { map.put(key, value); }
        @Override public void remove(String key) { map.remove(key); }
        @Override public Set<String> keys() { return new LinkedHashSet<>(map.keySet()); }
    }
}
