package burp.openapirbactester;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Immutable model for a single API endpoint parsed from an OpenAPI specification.
 * Holds HTTP method, path, server, parameters, description, and the names of any
 * security schemes required by the operation.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class ApiEndpoint {
    private final int index;
    private final String scheme;
    private final String method;
    private final String server;
    private final String path;
    private final List<ParameterInfo> parameters;
    private final String description;
    private final List<String> requiredSchemes;
    private final List<String> tags;

    public ApiEndpoint(int index, String scheme, String method, String server, String path,
                       List<ParameterInfo> parameters, String description) {
        this(index, scheme, method, server, path, parameters, description, null, null);
    }

    public ApiEndpoint(int index, String scheme, String method, String server, String path,
                       List<ParameterInfo> parameters, String description,
                       List<String> requiredSchemes, List<String> tags) {
        this.index = index;
        this.scheme = scheme != null ? scheme : "https";
        this.method = method != null ? method : "GET";
        this.server = server != null ? server : "";
        this.path = path != null ? path : "/";
        this.parameters = parameters != null ? parameters : new ArrayList<>();
        this.description = description != null ? description : "";
        this.requiredSchemes = requiredSchemes != null
                ? Collections.unmodifiableList(new ArrayList<>(requiredSchemes))
                : Collections.emptyList();
        this.tags = tags != null
                ? Collections.unmodifiableList(new ArrayList<>(tags))
                : Collections.emptyList();
    }

    public int getIndex() {
        return index;
    }

    public String getScheme() {
        return scheme;
    }

    public String getMethod() {
        return method;
    }

    public String getServer() {
        return server;
    }

    public String getPath() {
        return path;
    }

    public List<ParameterInfo> getParameters() {
        return parameters;
    }

    /**
     * True when the operation addresses a specific object via a path template
     * ({@code /users/{id}}). Such endpoints are where horizontal (same-tier) authorization
     * bugs live, so the RBAC classifier applies its identical-body check only to them. The
     * template is the signal rather than declared parameters: path-item-level parameters are
     * not merged into operations by the parser, and some specs never declare them at all.
     */
    public boolean isObjectScoped() {
        return path.indexOf('{') >= 0;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Names of the security schemes this operation requires, as declared in the
     * spec. Empty means either "no declared security" or "explicitly public
     * ({@code security: []})" — the caller can't distinguish those from this
     * alone; the presence of a global default is a {@link OpenAPIParser.ParseResult}
     * concern.
     */
    public List<String> getRequiredSchemes() {
        return requiredSchemes;
    }

    /** OpenAPI operation tags (e.g., "Admin", "Users"). Useful for RBAC tier inference. */
    public List<String> getTags() {
        return tags;
    }

    /**
     * Describes a single parameter (path, query, header, or cookie) for an endpoint.
     * Used for insertion point computation and display.
     */
    public static class ParameterInfo {
        private final String name;
        private final String location; // "path", "query", "header", "cookie"
        private final String placeholderValue;

        public ParameterInfo(String name, String location, String placeholderValue) {
            this.name = name;
            this.location = location;
            this.placeholderValue = placeholderValue != null ? placeholderValue : "";
        }

        public String getName() {
            return name;
        }

        public String getLocation() {
            return location;
        }

        public String getPlaceholderValue() {
            return placeholderValue;
        }
    }
}
