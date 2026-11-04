package burp.openapirbactester;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class MontoyaRbacHttpSenderTest {

    private Http http;
    private RequestGenerator generator;
    private MontoyaRbacHttpSender sender;

    @BeforeEach
    void setUp() {
        http = mock(Http.class);
        generator = mock(RequestGenerator.class);
        sender = new MontoyaRbacHttpSender(http, generator);
    }

    private static ApiEndpoint endpoint() {
        return new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/ping", List.of(), "");
    }

    @Test
    void send_populates200Result() {
        HttpRequest built = mock(HttpRequest.class);
        when(generator.buildRequest(any(), any(), any())).thenReturn(built);

        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(1234);
        when(response.body()).thenReturn(body);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(built)).thenReturn(rr);

        RbacHttpSender.SendResult result = sender.send(endpoint(), AuthConfig.empty(), null);

        assertEquals(200, result.cell().statusCode());
        assertEquals(1234L, result.cell().bodySize());
        assertSame(rr, result.raw());
    }

    @Test
    void send_nullResponseFromHttp_returnsErrorCell() {
        HttpRequest built = mock(HttpRequest.class);
        when(generator.buildRequest(any(), any(), any())).thenReturn(built);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(null);
        when(http.sendRequest(built)).thenReturn(rr);

        RbacHttpSender.SendResult result = sender.send(endpoint(), AuthConfig.empty(), null);

        assertTrue(result.cell().isError());
        assertEquals("no response", result.cell().errorMessage());
        assertSame(rr, result.raw());
    }

    @Test
    void send_httpThrows_returnsErrorCell() {
        HttpRequest built = mock(HttpRequest.class);
        when(generator.buildRequest(any(), any(), any())).thenReturn(built);
        when(http.sendRequest(built)).thenThrow(new RuntimeException("connection refused"));

        RbacHttpSender.SendResult result = sender.send(endpoint(), AuthConfig.empty(), null);

        assertTrue(result.cell().isError());
        assertTrue(result.cell().errorMessage().contains("connection refused"));
        assertNull(result.raw());
    }

    @Test
    void send_generatorThrows_returnsErrorCellWithoutHitting_http() {
        when(generator.buildRequest(any(), any(), any()))
                .thenThrow(new RuntimeException("bad path template"));

        RbacHttpSender.SendResult result = sender.send(endpoint(), AuthConfig.empty(), null);

        assertTrue(result.cell().isError());
        assertTrue(result.cell().errorMessage().contains("request build failed"));
        verifyNoInteractions(http);
    }

    @Test
    void send_hashesResponseBody_soIdenticalBodiesCompareEqual() {
        HttpRequest built = mock(HttpRequest.class);
        when(generator.buildRequest(any(), any(), any())).thenReturn(built);

        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(3);
        when(body.getBytes()).thenReturn("abc".getBytes());
        when(response.body()).thenReturn(body);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(built)).thenReturn(rr);

        var result = sender.send(endpoint(), AuthConfig.empty(), null);

        // SHA-256("abc")
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                result.cell().bodyHash());
    }

    @Test
    void send_emptyBody_hasNoHash_soItCannotCollideAcrossIdentities() {
        HttpRequest built = mock(HttpRequest.class);
        when(generator.buildRequest(any(), any(), any())).thenReturn(built);

        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 204);
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(0);
        when(body.getBytes()).thenReturn(new byte[0]);
        when(response.body()).thenReturn(body);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(built)).thenReturn(rr);

        var result = sender.send(endpoint(), AuthConfig.empty(), null);

        assertNull(result.cell().bodyHash());
    }

    @Test
    void send_nullBody_countsAsZeroSize() {
        HttpRequest built = mock(HttpRequest.class);
        when(generator.buildRequest(any(), any(), any())).thenReturn(built);

        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 204);
        when(response.body()).thenReturn(null);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(built)).thenReturn(rr);

        var result = sender.send(endpoint(), AuthConfig.empty(), null);

        assertEquals(204, result.cell().statusCode());
        assertEquals(0L, result.cell().bodySize());
        assertNull(result.cell().bodyHash());
    }

    @Test
    void send_blankOverride_treatedAsNullForGenerator() {
        HttpRequest built = mock(HttpRequest.class);
        when(generator.buildRequest(any(), any(), any())).thenReturn(built);
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(0);
        when(response.body()).thenReturn(body);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        when(http.sendRequest(built)).thenReturn(rr);

        sender.send(endpoint(), AuthConfig.empty(), "   ");

        // Verify we passed null (not the blank string) to the generator.
        ArgumentCaptor<String> baseCap = ArgumentCaptor.forClass(String.class);
        verify(generator).buildRequest(any(), baseCap.capture(), any());
        assertNull(baseCap.getValue());
    }
}
