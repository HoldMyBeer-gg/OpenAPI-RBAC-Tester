package burp.openapirbactester;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.SwaggerParseResult;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses OpenAPI 2.0 (Swagger) and 3.x specifications into {@link ApiEndpoint} lists.
 * Uses Swagger Parser for JSON and YAML. Strips leading shell prompts from pasted content.
 * Also extracts declared {@code securitySchemes} and per-operation {@code security}
 * requirements for auth-aware flows.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class OpenAPIParser {

    public ParseResult parse(String location, String specContent) {
        List<ApiEndpoint> endpoints = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        List<SecuritySchemeInfo> securitySchemes = new ArrayList<>();
        String defaultServer = "";

        if (specContent == null || specContent.isBlank()) {
            errors.add("Spec content is empty");
            return new ParseResult(endpoints, errors, defaultServer, securitySchemes);
        }

        String cleaned = stripLeadingShellPrompt(specContent.trim());
        if (!looksLikeSpec(cleaned)) {
            errors.add("Not an OpenAPI spec: " + describeLocation(location)
                    + " does not start with a JSON object or an 'openapi:'/'swagger:' YAML key.");
            return new ParseResult(endpoints, errors, defaultServer, securitySchemes);
        }
        SwaggerParseResult parseResult = new OpenAPIV3Parser().readContents(cleaned, null, null);
        OpenAPI openAPI = parseResult.getOpenAPI();

        if (openAPI == null) {
            if (parseResult.getMessages() != null && !parseResult.getMessages().isEmpty()) {
                errors.addAll(parseResult.getMessages());
            } else {
                errors.add("Failed to parse OpenAPI spec");
            }
            return new ParseResult(endpoints, errors, defaultServer, securitySchemes);
        }

        if (parseResult.getMessages() != null) {
            errors.addAll(parseResult.getMessages());
        }

        defaultServer = resolveDefaultServer(openAPI);
        securitySchemes = extractSecuritySchemes(openAPI);
        List<String> globalSecurityNames = extractSecurityRequirementNames(openAPI.getSecurity());

        Map<String, PathItem> paths = openAPI.getPaths();
        if (paths == null) {
            return new ParseResult(endpoints, errors, defaultServer, securitySchemes);
        }

        int index = 1;
        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            if (pathItem == null) continue;

            Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();
            if (operations == null) continue;

            for (Map.Entry<PathItem.HttpMethod, Operation> opEntry : operations.entrySet()) {
                PathItem.HttpMethod httpMethod = opEntry.getKey();
                Operation operation = opEntry.getValue();
                if (operation == null) continue;

                String method = httpMethod.name();
                String scheme = extractScheme(defaultServer);
                String server = defaultServer;
                String description = operation.getSummary() != null ? operation.getSummary()
                        : (operation.getDescription() != null ? operation.getDescription() : "");

                List<ApiEndpoint.ParameterInfo> params = new ArrayList<>();
                if (operation.getParameters() != null) {
                    for (Parameter p : operation.getParameters()) {
                        if (p == null) continue;
                        String paramName = p.getName();
                        String paramIn = p.getIn() != null ? p.getIn().toLowerCase() : "query";
                        String placeholder;
                        if ("path".equals(paramIn)) {
                            placeholder = derivePathPlaceholder(p);
                        } else {
                            // Query/header/cookie placeholders remain empty — Scanner/Intruder
                            // will inject payloads there, and sending empty strings is a
                            // reasonable default for a preview request.
                            placeholder = "";
                        }
                        params.add(new ApiEndpoint.ParameterInfo(paramName, paramIn, placeholder));
                    }
                }

                List<String> requiredSchemes = operation.getSecurity() != null
                        ? extractSecurityRequirementNames(operation.getSecurity())
                        : globalSecurityNames;
                List<String> tags = operation.getTags() != null
                        ? new ArrayList<>(operation.getTags())
                        : Collections.emptyList();

                ApiEndpoint endpoint = new ApiEndpoint(
                        index++, scheme, method, server, path, params, description,
                        requiredSchemes, tags);
                endpoints.add(endpoint);
            }
        }

        return new ParseResult(endpoints, errors, defaultServer, securitySchemes);
    }

    private String resolveDefaultServer(OpenAPI openAPI) {
        List<Server> servers = openAPI.getServers();
        if (servers != null && !servers.isEmpty()) {
            Server s = servers.get(0);
            if (s != null && s.getUrl() != null && !s.getUrl().isBlank()) {
                return normalizeServerUrl(s.getUrl());
            }
        }

        return "";
    }

    private String normalizeServerUrl(String url) {
        if (url == null) return "";
        url = url.trim();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }

    /**
     * Extracts every declared security scheme from {@code components.securitySchemes},
     * mapping swagger-parser types to our internal {@link SecuritySchemeInfo}. Preserves
     * declaration order via LinkedHashMap semantics in the underlying parser.
     */
    /**
     * Picks a syntactically-valid path-parameter placeholder from a swagger-parser
     * {@link Parameter}. Uses {@code example} when present, falling back to schema
     * {@code type}/{@code format}-aware defaults. Returns {@value PlaceholderGenerator#DEFAULT}
     * when no schema info is available.
     */
    static String derivePathPlaceholder(Parameter p) {
        String type = null;
        String format = null;
        String example = null;
        if (p.getExample() != null) example = String.valueOf(p.getExample());
        if (example == null && p.getExamples() != null && !p.getExamples().isEmpty()) {
            var firstExample = p.getExamples().values().iterator().next();
            if (firstExample != null && firstExample.getValue() != null) {
                example = String.valueOf(firstExample.getValue());
            }
        }
        io.swagger.v3.oas.models.media.Schema<?> schema = p.getSchema();
        if (schema != null) {
            type = schema.getType();
            format = schema.getFormat();
            if (example == null && schema.getExample() != null) {
                example = String.valueOf(schema.getExample());
            }
            // Fall back to first enum value if still empty.
            if (example == null && schema.getEnum() != null && !schema.getEnum().isEmpty()) {
                example = String.valueOf(schema.getEnum().get(0));
            }
        }
        return PlaceholderGenerator.placeholderFor(type, format, example);
    }

    static List<SecuritySchemeInfo> extractSecuritySchemes(OpenAPI openAPI) {
        Components components = openAPI.getComponents();
        if (components == null || components.getSecuritySchemes() == null) {
            return new ArrayList<>();
        }
        Map<String, SecurityScheme> rawSchemes = new LinkedHashMap<>(components.getSecuritySchemes());
        List<SecuritySchemeInfo> result = new ArrayList<>();
        for (Map.Entry<String, SecurityScheme> entry : rawSchemes.entrySet()) {
            String name = entry.getKey();
            SecurityScheme ss = entry.getValue();
            if (ss == null || ss.getType() == null) {
                result.add(SecuritySchemeInfo.other(name));
                continue;
            }
            switch (ss.getType()) {
                case HTTP:
                    String httpScheme = ss.getScheme() != null ? ss.getScheme().toLowerCase() : "";
                    if ("bearer".equals(httpScheme)) {
                        result.add(SecuritySchemeInfo.bearer(name, ss.getBearerFormat()));
                    } else if ("basic".equals(httpScheme)) {
                        result.add(SecuritySchemeInfo.basic(name));
                    } else {
                        result.add(SecuritySchemeInfo.other(name));
                    }
                    break;
                case APIKEY:
                    String inLocation = ss.getIn() != null ? ss.getIn().toString().toLowerCase() : "header";
                    result.add(SecuritySchemeInfo.apiKey(name, inLocation, ss.getName()));
                    break;
                case OAUTH2:
                    result.add(SecuritySchemeInfo.oauth2(name));
                    break;
                case OPENIDCONNECT:
                    result.add(SecuritySchemeInfo.openIdConnect(name));
                    break;
                default:
                    result.add(SecuritySchemeInfo.other(name));
            }
        }
        return result;
    }

    /**
     * Collects the names of all security schemes referenced by a list of
     * {@link SecurityRequirement}s. Each requirement is a Map&lt;schemeName, scopes&gt;;
     * we keep the keys (scheme names), discard the scope lists (OAuth2-only).
     * An empty list input returns an empty result — an explicit {@code security: []}
     * override means "no auth required."
     */
    static List<String> extractSecurityRequirementNames(List<SecurityRequirement> requirements) {
        if (requirements == null || requirements.isEmpty()) return Collections.emptyList();
        List<String> names = new ArrayList<>();
        for (SecurityRequirement req : requirements) {
            if (req == null) continue;
            for (String name : req.keySet()) {
                if (name != null && !name.isBlank() && !names.contains(name)) {
                    names.add(name);
                }
            }
        }
        return names;
    }

    /**
     * Strips leading lines that look like shell prompts or commands (e.g.
     * {@code anon@MBPC:/mnt/d$ cat openapi.json}) until the first line matching
     * {@code openapi:}, {@code swagger:}, or a JSON opening brace.
     *
     * @param content raw pasted content
     * @return content starting from the first OpenAPI/Swagger line, or original if none found
     */
    /**
     * Content-based check that runs before the swagger parser. The file picker does
     * not filter by extension (the spec may be called anything), so this is what
     * stops a CSV, prose, or a bare JSON array from reaching Jackson and surfacing
     * as a deserialisation stack trace.
     */
    static boolean looksLikeSpec(String content) {
        if (content == null) return false;
        String head = content.stripLeading();
        return head.startsWith("{") || head.startsWith("openapi:") || head.startsWith("swagger:");
    }

    private static String describeLocation(String location) {
        return (location == null || location.isBlank()) ? "the selected content" : location;
    }

    private static String stripLeadingShellPrompt(String content) {
        if (content == null || content.isEmpty()) return content;
        String[] lines = content.split("\\r?\\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.startsWith("openapi:") || line.startsWith("swagger:") || line.startsWith("{")) {
                return String.join("\n", java.util.Arrays.copyOfRange(lines, i, lines.length));
            }
        }
        return content;
    }

    private String extractScheme(String serverUrl) {
        if (serverUrl == null || serverUrl.isBlank()) return "https";
        try {
            URI uri = new URI(serverUrl);
            String scheme = uri.getScheme();
            return scheme != null ? scheme : "https";
        } catch (URISyntaxException e) {
            return "https";
        }
    }

    /**
     * Result of parsing an OpenAPI specification. Contains the parsed endpoints,
     * any warning or error messages from the parser, the default server URL, and
     * the list of declared security schemes.
     */
    public static class ParseResult {
        private final List<ApiEndpoint> endpoints;
        private final List<String> messages;
        private final String defaultServer;
        private final List<SecuritySchemeInfo> securitySchemes;

        public ParseResult(List<ApiEndpoint> endpoints, List<String> messages, String defaultServer) {
            this(endpoints, messages, defaultServer, Collections.emptyList());
        }

        public ParseResult(List<ApiEndpoint> endpoints, List<String> messages, String defaultServer,
                           List<SecuritySchemeInfo> securitySchemes) {
            this.endpoints = endpoints;
            this.messages = messages;
            this.defaultServer = defaultServer;
            this.securitySchemes = securitySchemes != null
                    ? Collections.unmodifiableList(new ArrayList<>(securitySchemes))
                    : Collections.emptyList();
        }

        public List<ApiEndpoint> getEndpoints() {
            return endpoints;
        }

        public List<String> getMessages() {
            return messages;
        }

        public String getDefaultServer() {
            return defaultServer;
        }

        public List<SecuritySchemeInfo> getSecuritySchemes() {
            return securitySchemes;
        }
    }
}
