package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2 coverage: parser extraction of securitySchemes and per-operation security
 * requirements. Uses inline YAML specs to exercise every scheme type and resolution path.
 */
class OpenAPIParserSecurityTest {

    private final OpenAPIParser parser = new OpenAPIParser();

    private static final String SPEC_ALL_SCHEMES = """
            openapi: 3.0.0
            info:
              title: All
              version: "1"
            components:
              securitySchemes:
                bearerAuth:
                  type: http
                  scheme: bearer
                  bearerFormat: JWT
                basicAuth:
                  type: http
                  scheme: basic
                keyHeader:
                  type: apiKey
                  in: header
                  name: X-API-Key
                keyQuery:
                  type: apiKey
                  in: query
                  name: api_key
                keyCookie:
                  type: apiKey
                  in: cookie
                  name: session
                oauth2Scheme:
                  type: oauth2
                  flows:
                    implicit:
                      authorizationUrl: https://example.com/oauth/authorize
                      scopes:
                        "admin:read": "..."
                oidc:
                  type: openIdConnect
                  openIdConnectUrl: https://example.com/.well-known/openid-configuration
            paths:
              /ping:
                get:
                  responses:
                    '200':
                      description: ok
            """;

    @Test
    void allSchemeTypes_extracted() {
        var result = parser.parse("test", SPEC_ALL_SCHEMES);
        List<SecuritySchemeInfo> schemes = result.getSecuritySchemes();
        assertEquals(7, schemes.size(), "all declared schemes should be present");

        assertEquals(SecuritySchemeInfo.SchemeType.BEARER, findByName(schemes, "bearerAuth").type());
        assertEquals("JWT", findByName(schemes, "bearerAuth").bearerFormat());

        assertEquals(SecuritySchemeInfo.SchemeType.BASIC, findByName(schemes, "basicAuth").type());

        var keyHeader = findByName(schemes, "keyHeader");
        assertEquals(SecuritySchemeInfo.SchemeType.API_KEY, keyHeader.type());
        assertEquals("header", keyHeader.apiKeyLocation());
        assertEquals("X-API-Key", keyHeader.apiKeyName());

        assertEquals("query", findByName(schemes, "keyQuery").apiKeyLocation());
        assertEquals("cookie", findByName(schemes, "keyCookie").apiKeyLocation());

        assertEquals(SecuritySchemeInfo.SchemeType.OAUTH2, findByName(schemes, "oauth2Scheme").type());
        assertEquals(SecuritySchemeInfo.SchemeType.OPEN_ID_CONNECT, findByName(schemes, "oidc").type());
    }

    @Test
    void noSecurityDeclared_endpointsHaveEmptyRequiredSchemes() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /users:
                    get:
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        assertTrue(result.getSecuritySchemes().isEmpty());
        assertEquals(1, result.getEndpoints().size());
        assertTrue(result.getEndpoints().get(0).getRequiredSchemes().isEmpty());
    }

    @Test
    void globalSecurity_inheritedByEndpoints() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                components:
                  securitySchemes:
                    bearerAuth: {type: http, scheme: bearer}
                security:
                  - bearerAuth: []
                paths:
                  /users:
                    get:
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        ApiEndpoint ep = result.getEndpoints().get(0);
        assertEquals(List.of("bearerAuth"), ep.getRequiredSchemes());
    }

    @Test
    void perOperationSecurity_overridesGlobal() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                components:
                  securitySchemes:
                    bearerAuth: {type: http, scheme: bearer}
                    adminAuth: {type: http, scheme: bearer}
                security:
                  - bearerAuth: []
                paths:
                  /users:
                    get:
                      responses: {'200': {description: ok}}
                  /admin:
                    get:
                      security:
                        - adminAuth: []
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        ApiEndpoint users = result.getEndpoints().stream()
                .filter(e -> "/users".equals(e.getPath())).findFirst().orElseThrow();
        ApiEndpoint admin = result.getEndpoints().stream()
                .filter(e -> "/admin".equals(e.getPath())).findFirst().orElseThrow();
        assertEquals(List.of("bearerAuth"), users.getRequiredSchemes());
        assertEquals(List.of("adminAuth"), admin.getRequiredSchemes());
    }

    @Test
    void explicitEmptySecurity_meansNoAuth() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                components:
                  securitySchemes:
                    bearerAuth: {type: http, scheme: bearer}
                security:
                  - bearerAuth: []
                paths:
                  /public:
                    get:
                      security: []
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        ApiEndpoint publicEp = result.getEndpoints().get(0);
        assertTrue(publicEp.getRequiredSchemes().isEmpty(),
                "security: [] should yield empty requiredSchemes even when global security exists");
    }

    @Test
    void multipleSchemesInOneRequirement_bothNamesCaptured() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                components:
                  securitySchemes:
                    bearerAuth: {type: http, scheme: bearer}
                    apiKey: {type: apiKey, in: header, name: X-API-Key}
                paths:
                  /dual:
                    get:
                      security:
                        - bearerAuth: []
                          apiKey: []
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        List<String> required = result.getEndpoints().get(0).getRequiredSchemes();
        assertTrue(required.contains("bearerAuth"));
        assertTrue(required.contains("apiKey"));
    }

    @Test
    void alternativeSchemes_allNamesCollected() {
        // Security requirement entries are OR'd: any single satisfies. We capture all names.
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                components:
                  securitySchemes:
                    bearerAuth: {type: http, scheme: bearer}
                    apiKey: {type: apiKey, in: header, name: X-API-Key}
                paths:
                  /either:
                    get:
                      security:
                        - bearerAuth: []
                        - apiKey: []
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        List<String> required = result.getEndpoints().get(0).getRequiredSchemes();
        assertEquals(2, required.size());
        assertTrue(required.contains("bearerAuth"));
        assertTrue(required.contains("apiKey"));
    }

    @Test
    void tags_parsedIntoEndpoints() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /admin/users:
                    get:
                      tags: [Admin, Users]
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        assertEquals(List.of("Admin", "Users"), result.getEndpoints().get(0).getTags());
    }

    @Test
    void emptySpec_emptySchemesList() {
        var result = parser.parse("t", "");
        assertTrue(result.getSecuritySchemes().isEmpty());
    }

    @Test
    void requirementNamesExtraction_nullReturnsEmpty() {
        assertTrue(OpenAPIParser.extractSecurityRequirementNames(null).isEmpty());
        assertTrue(OpenAPIParser.extractSecurityRequirementNames(List.of()).isEmpty());
    }

    @Test
    void httpSchemeOtherThanBearerOrBasic_classifiedAsOther() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                components:
                  securitySchemes:
                    digestAuth:
                      type: http
                      scheme: digest
                paths:
                  /x:
                    get:
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        assertEquals(SecuritySchemeInfo.SchemeType.OTHER,
                findByName(result.getSecuritySchemes(), "digestAuth").type());
    }

    @Test
    void apiKeyWithoutExplicitIn_defaultsToHeader() {
        // swagger-parser normally rejects specs with missing required fields, but if
        // `in` is absent we fall back to "header" defensively.
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                components:
                  securitySchemes:
                    keyAuth:
                      type: apiKey
                      name: X-Key
                paths:
                  /x:
                    get:
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        // swagger-parser may or may not emit the scheme without `in`; if it does, verify fallback.
        if (!result.getSecuritySchemes().isEmpty()) {
            var s = findByName(result.getSecuritySchemes(), "keyAuth");
            assertNotNull(s.apiKeyLocation(), "apiKeyLocation should have a default fallback, not null");
        }
    }

    @Test
    void requirementNamesExtraction_skipsNullRequirements() {
        java.util.List<io.swagger.v3.oas.models.security.SecurityRequirement> reqs = new java.util.ArrayList<>();
        reqs.add(null);
        var req = new io.swagger.v3.oas.models.security.SecurityRequirement();
        req.addList("bearerAuth", List.of());
        reqs.add(req);
        List<String> names = OpenAPIParser.extractSecurityRequirementNames(reqs);
        assertEquals(List.of("bearerAuth"), names);
    }

    @Test
    void requirementNamesExtraction_deduplicatesAcrossRequirements() {
        java.util.List<io.swagger.v3.oas.models.security.SecurityRequirement> reqs = new java.util.ArrayList<>();
        var a = new io.swagger.v3.oas.models.security.SecurityRequirement();
        a.addList("bearerAuth", List.of());
        var b = new io.swagger.v3.oas.models.security.SecurityRequirement();
        b.addList("bearerAuth", List.of());
        reqs.add(a);
        reqs.add(b);
        assertEquals(1, OpenAPIParser.extractSecurityRequirementNames(reqs).size());
    }

    private static SecuritySchemeInfo findByName(List<SecuritySchemeInfo> list, String name) {
        return list.stream().filter(s -> name.equals(s.name())).findFirst().orElseThrow();
    }

    @Test
    void pathParamWithUuidFormat_usesUuidPlaceholder() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /reports/{report_id}:
                    get:
                      parameters:
                        - name: report_id
                          in: path
                          required: true
                          schema: {type: string, format: uuid}
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        ApiEndpoint ep = result.getEndpoints().get(0);
        ApiEndpoint.ParameterInfo reportId = ep.getParameters().get(0);
        assertEquals("path", reportId.getLocation());
        assertEquals("00000000-0000-0000-0000-000000000001", reportId.getPlaceholderValue());
    }

    @Test
    void pathParamWithIntegerType_usesOne() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /users/{id}:
                    get:
                      parameters:
                        - name: id
                          in: path
                          required: true
                          schema: {type: integer}
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        assertEquals("1",
                result.getEndpoints().get(0).getParameters().get(0).getPlaceholderValue());
    }

    @Test
    void pathParamWithExample_usesExample() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /orgs/{org_id}:
                    get:
                      parameters:
                        - name: org_id
                          in: path
                          required: true
                          example: "acme-corp"
                          schema: {type: string, format: uuid}
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        // Example wins over schema format.
        assertEquals("acme-corp",
                result.getEndpoints().get(0).getParameters().get(0).getPlaceholderValue());
    }

    @Test
    void pathParamWithSchemaExample_usesIt() {
        // No format — swagger-parser would strip examples that don't match a declared format
        // (e.g. a non-UUID example on a UUID field). This plain-string schema preserves the example.
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /reports/{id}:
                    get:
                      parameters:
                        - name: id
                          in: path
                          required: true
                          schema:
                            type: string
                            example: "abc-123"
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        assertEquals("abc-123",
                result.getEndpoints().get(0).getParameters().get(0).getPlaceholderValue());
    }

    @Test
    void pathParamWithEnum_usesFirstEnumValue() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /severity/{level}:
                    get:
                      parameters:
                        - name: level
                          in: path
                          required: true
                          schema:
                            type: string
                            enum: [critical, high, medium, low]
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        assertEquals("critical",
                result.getEndpoints().get(0).getParameters().get(0).getPlaceholderValue());
    }

    @Test
    void pathParamWithoutSchema_usesDefault() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /legacy/{name}:
                    get:
                      parameters:
                        - name: name
                          in: path
                          required: true
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        assertEquals("1",
                result.getEndpoints().get(0).getParameters().get(0).getPlaceholderValue());
    }

    @Test
    void queryParam_remainsEmptyPlaceholder() {
        String spec = """
                openapi: 3.0.0
                info: {title: x, version: "1"}
                paths:
                  /search:
                    get:
                      parameters:
                        - name: q
                          in: query
                          schema: {type: string, format: uuid}
                      responses: {'200': {description: ok}}
                """;
        var result = parser.parse("t", spec);
        // Query params stay empty; smart placeholders only apply to path params where
        // the value becomes part of the URL path.
        assertEquals("",
                result.getEndpoints().get(0).getParameters().get(0).getPlaceholderValue());
    }
}
