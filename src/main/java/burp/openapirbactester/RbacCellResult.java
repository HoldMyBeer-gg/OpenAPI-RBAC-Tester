package burp.openapirbactester;

/**
 * Outcome of sending a single endpoint × identity combination during an RBAC comparison.
 * Immutable. Pure data — no Montoya dependencies, so classifiers remain testable without
 * a Burp runtime. The dialog caches the original {@code HttpRequestResponse} separately
 * for click-through.
 *
 * @param statusCode   HTTP status, or {@code -1} if the request failed before a response.
 * @param bodySize     response body length in bytes; {@code -1} on error.
 * @param elapsedMs    wall-clock request duration.
 * @param errorMessage populated only when {@code statusCode == -1}; null otherwise.
 * @param bodyHash     content hash of the response body (SHA-256 hex), or null when there
 *                     was no body or the sender did not compute one. Lets the classifier
 *                     tell "two identities got the same object" from "two identities got
 *                     their own object" without keeping bodies in memory.
 */
public record RbacCellResult(int statusCode, long bodySize, long elapsedMs, String errorMessage, String bodyHash) {

    public RbacCellResult(int statusCode, long bodySize, long elapsedMs, String errorMessage) {
        this(statusCode, bodySize, elapsedMs, errorMessage, null);
    }

    public static RbacCellResult ok(int statusCode, long bodySize, long elapsedMs) {
        return new RbacCellResult(statusCode, bodySize, elapsedMs, null, null);
    }

    public static RbacCellResult ok(int statusCode, long bodySize, long elapsedMs, String bodyHash) {
        return new RbacCellResult(statusCode, bodySize, elapsedMs, null, bodyHash);
    }

    public static RbacCellResult error(String message, long elapsedMs) {
        return new RbacCellResult(-1, -1, elapsedMs, message == null ? "unknown error" : message, null);
    }

    public boolean isError() { return statusCode < 0; }
    public boolean is2xx() { return statusCode >= 200 && statusCode < 300; }
    public boolean is3xx() { return statusCode >= 300 && statusCode < 400; }
    public boolean isAuthDenied() { return statusCode == 401 || statusCode == 403; }
    public boolean isNotFound() { return statusCode == 404; }
    public boolean is5xx() { return statusCode >= 500 && statusCode < 600; }

    /** Short status label for display — e.g. "200", "403", "err". */
    public String shortLabel() {
        return isError() ? "err" : Integer.toString(statusCode);
    }
}
