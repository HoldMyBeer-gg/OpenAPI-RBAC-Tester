package burp.openapirbactester;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.intruder.HttpRequestTemplateGenerationOptions;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Builds {@link HttpRequest} and {@link HttpRequestTemplate} from {@link ApiEndpoint}s.
 * Handles path/query param substitution, optional auth injection, and Intruder templates
 * with auto-marked insertion points.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class RequestGenerator {

    private static final String PATH_PARAM_PLACEHOLDER = "1";
    private static final String BODY_PLACEHOLDER = "{}";

    public byte[] buildRequestBytes(ApiEndpoint endpoint, String baseUrlOverride) {
        return buildRequestBytes(endpoint, baseUrlOverride, AuthConfig.empty());
    }

    public byte[] buildRequestBytes(ApiEndpoint endpoint, String baseUrlOverride, AuthConfig auth) {
        return buildRequestString(endpoint, baseUrlOverride, auth).getBytes(StandardCharsets.UTF_8);
    }

    private String buildRequestString(ApiEndpoint endpoint, String baseUrlOverride, AuthConfig auth) {
        if (auth == null) auth = AuthConfig.empty();

        String server = (baseUrlOverride != null && !baseUrlOverride.isBlank())
                ? baseUrlOverride
                : endpoint.getServer();
        if (server == null || server.isEmpty()) {
            server = "https://localhost";
        }
        server = server.endsWith("/") ? server.substring(0, server.length() - 1) : server;

        String path = substitutePathParams(endpoint.getPath(), endpoint.getParameters());
        StringBuilder query = new StringBuilder();
        for (ApiEndpoint.ParameterInfo p : endpoint.getParameters()) {
            if ("query".equals(p.getLocation())) {
                if (query.length() > 0) query.append("&");
                query.append(p.getName()).append("=").append(p.getPlaceholderValue());
            }
        }
        if (auth.hasApiKey() && auth.apiKeyLocation() == AuthConfig.ApiKeyLocation.QUERY) {
            if (query.length() > 0) query.append("&");
            query.append(urlEncode(auth.apiKeyName())).append("=").append(urlEncode(auth.apiKeyValue()));
        }
        String pathWithQuery = path + (query.length() > 0 ? "?" + query : "");

        boolean hasBody = "POST".equalsIgnoreCase(endpoint.getMethod())
                || "PUT".equalsIgnoreCase(endpoint.getMethod())
                || "PATCH".equalsIgnoreCase(endpoint.getMethod());

        StringBuilder request = new StringBuilder();
        request.append(endpoint.getMethod()).append(" ").append(pathWithQuery).append(" HTTP/1.1\r\n");
        try {
            URI uri = new URI(server);
            String host = uri.getHost();
            int port = uri.getPort();
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            if (port <= 0) port = secure ? 443 : 80;
            request.append("Host: ").append(host);
            if ((secure && port != 443) || (!secure && port != 80)) {
                request.append(":").append(port);
            }
            request.append("\r\n");
        } catch (URISyntaxException e) {
            request.append("Host: localhost\r\n");
        }
        request.append("User-Agent: OpenAPI-RBAC-Tester/1.0\r\n");
        appendAuthHeaders(request, auth);
        if (hasBody) {
            int bodyLength = BODY_PLACEHOLDER.getBytes(StandardCharsets.UTF_8).length;
            request.append("Content-Type: application/json\r\n");
            request.append("Content-Length: ").append(bodyLength).append("\r\n");
        }
        request.append("\r\n");
        if (hasBody) {
            request.append(BODY_PLACEHOLDER);
        }

        return request.toString();
    }

    /**
     * Appends auth and user-supplied headers. Bearer/Basic take precedence if both set
     * (Basic wins last-write). API key header/cookie live on their own line; query keys
     * are handled in the query string. User-supplied extra headers are appended last so
     * they override earlier headers on collision.
     */
    private void appendAuthHeaders(StringBuilder request, AuthConfig auth) {
        if (auth.hasBearer()) {
            request.append("Authorization: Bearer ").append(auth.bearerToken()).append("\r\n");
        }
        if (auth.hasBasic()) {
            request.append("Authorization: ").append(auth.basicAuthorizationHeaderValue()).append("\r\n");
        }
        if (auth.hasApiKey()) {
            switch (auth.apiKeyLocation()) {
                case HEADER:
                    request.append(auth.apiKeyName()).append(": ").append(auth.apiKeyValue()).append("\r\n");
                    break;
                case COOKIE:
                    request.append("Cookie: ").append(auth.apiKeyName()).append("=").append(auth.apiKeyValue()).append("\r\n");
                    break;
                case QUERY:
                    // Already applied to query string.
                    break;
            }
        }
        for (AuthConfig.HeaderPair h : auth.extraHeaders()) {
            request.append(h.name()).append(": ").append(h.value()).append("\r\n");
        }
    }

    public HttpRequest buildRequest(ApiEndpoint endpoint, String baseUrlOverride) {
        return buildRequest(endpoint, baseUrlOverride, AuthConfig.empty());
    }

    public HttpRequest buildRequest(ApiEndpoint endpoint, String baseUrlOverride, AuthConfig auth) {
        String requestStr = buildRequestString(endpoint, baseUrlOverride, auth);
        String server = (baseUrlOverride != null && !baseUrlOverride.isBlank())
                ? baseUrlOverride
                : (endpoint.getServer() != null && !endpoint.getServer().isEmpty() ? endpoint.getServer() : "https://localhost");
        server = server.endsWith("/") ? server.substring(0, server.length() - 1) : server;
        return HttpRequest.httpRequest(HttpService.httpService(server), requestStr);
    }

    public HttpRequestTemplate buildIntruderTemplate(ApiEndpoint endpoint, String baseUrlOverride) {
        return buildIntruderTemplate(endpoint, baseUrlOverride, AuthConfig.empty());
    }

    public HttpRequestTemplate buildIntruderTemplate(ApiEndpoint endpoint, String baseUrlOverride, AuthConfig auth) {
        HttpRequest request = buildRequest(endpoint, baseUrlOverride, auth);
        return HttpRequestTemplate.httpRequestTemplate(
                request,
                HttpRequestTemplateGenerationOptions.REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS
        );
    }

    private String substitutePathParams(String path, List<ApiEndpoint.ParameterInfo> params) {
        String result = path;
        for (ApiEndpoint.ParameterInfo p : params) {
            if ("path".equals(p.getLocation())) {
                String placeholder = p.getPlaceholderValue();
                if (placeholder == null || placeholder.isEmpty()) placeholder = PATH_PARAM_PLACEHOLDER;
                result = result.replace("{" + p.getName() + "}", placeholder);
            }
        }
        result = Pattern.compile("\\{[^}]+\\}").matcher(result).replaceAll(PATH_PARAM_PLACEHOLDER);
        return result;
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
