package burp.openapibifrost;

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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Headless tests for the Montoya wiring inside {@link OpenAPIBifrostTab}. Swing panels
 * build fine without a display; only top-level windows need one, so the RBAC dialog
 * itself stays out of these tests.
 */
class OpenAPIBifrostTabTest {

    private static final String SPEC_URL = "https://api.example.test/openapi.json";

    private MontoyaApi api;
    private Http http;
    private MontoyaObjectFactory factory;
    private OpenAPIBifrostTab tab;

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

        tab = new OpenAPIBifrostTab(api, new IdentityStore(new InMemoryPrefs()));
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
    void unload_abortsTrackedComparisonRuns() {
        OpenAPIBifrostTab.AbortableRun run = mock(OpenAPIBifrostTab.AbortableRun.class);
        tab.trackRun(run);

        tab.unload();

        verify(run).abort();
    }

    @Test
    void unload_skipsRunsThatAlreadyFinished() {
        OpenAPIBifrostTab.AbortableRun run = mock(OpenAPIBifrostTab.AbortableRun.class);
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
