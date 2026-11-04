package burp.openapirbactester;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Production {@link RbacHttpSender} that builds a request via {@link RequestGenerator}
 * and fires it through Montoya's HTTP stack. Returns the raw {@link HttpRequestResponse}
 * in {@link SendResult#raw()} so the grid can open it in Repeater without replaying.
 */
public class MontoyaRbacHttpSender implements RbacHttpSender {

    private final Http http;
    private final RequestGenerator requestGenerator;

    public MontoyaRbacHttpSender(Http http, RequestGenerator requestGenerator) {
        this.http = http;
        this.requestGenerator = requestGenerator;
    }

    @Override
    public SendResult send(ApiEndpoint endpoint, AuthConfig auth, String baseUrlOverride) {
        HttpRequest req;
        try {
            String override = baseUrlOverride == null || baseUrlOverride.isBlank() ? null : baseUrlOverride;
            req = requestGenerator.buildRequest(endpoint, override, auth);
        } catch (Exception e) {
            return new SendResult(RbacCellResult.error("request build failed: " + e.getMessage(), 0), null);
        }

        long t0 = System.currentTimeMillis();
        try {
            HttpRequestResponse rr = http.sendRequest(req);
            long elapsed = System.currentTimeMillis() - t0;
            HttpResponse resp = rr.response();
            if (resp == null) {
                return new SendResult(RbacCellResult.error("no response", elapsed), rr);
            }
            long bodyLen = resp.body() != null ? resp.body().length() : 0;
            // No hash for empty bodies: a 204 carries no object, so two identical empties
            // must not read as "same object".
            String hash = bodyLen > 0 ? sha256Hex(resp.body().getBytes()) : null;
            return new SendResult(RbacCellResult.ok(resp.statusCode(), bodyLen, elapsed, hash), rr);
        } catch (Throwable t) {
            long elapsed = System.currentTimeMillis() - t0;
            return new SendResult(
                    RbacCellResult.error(t.getClass().getSimpleName() + ": " + t.getMessage(), elapsed),
                    null);
        }
    }

    static String sha256Hex(byte[] bytes) {
        if (bytes == null) return null;
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
