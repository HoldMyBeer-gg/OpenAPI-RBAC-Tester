package burp.openapirbactester;

/**
 * Strategy for actually sending a single endpoint × identity combination and producing
 * the resulting {@link RbacCellResult} plus an optional raw response object for
 * click-through. Exists as an interface so the runner can be unit-tested with a
 * deterministic fake instead of Montoya's live HTTP stack.
 */
@FunctionalInterface
public interface RbacHttpSender {
    SendResult send(ApiEndpoint endpoint, AuthConfig auth, String baseUrlOverride);

    /**
     * @param cell the logical outcome that the classifier and grid operate on
     * @param raw  production wraps {@link burp.api.montoya.http.message.HttpRequestResponse};
     *             tests pass {@code null}. Kept as {@code Object} to keep this interface
     *             pure and {@link RbacRunner} decoupled from Montoya types.
     */
    record SendResult(RbacCellResult cell, Object raw) {}
}
