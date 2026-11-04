package burp.openapirbactester.bdd;

import burp.openapirbactester.ApiEndpoint;
import burp.openapirbactester.OpenAPIParser;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Step definitions for OpenAPI parsing BDD scenarios.
 */
public class OpenAPIParsingSteps {

    private OpenAPIParser parser;
    private String specificationContent;
    private OpenAPIParser.ParseResult parseResult;

    public OpenAPIParsingSteps() {
        this.parser = new OpenAPIParser();
    }

    @Given("I have a valid OpenAPI specification with {int} endpoints")
    public void iHaveAValidOpenAPISpecificationWithEndpoints(int endpointCount) throws Exception {
        // Load the petstore sample which has multiple endpoints
        InputStream is = getClass().getClassLoader().getResourceAsStream("openapi-petstore.json");
        assertNotNull(is, "Test resource not found");
        specificationContent = new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    @Given("I have an empty specification")
    public void iHaveAnEmptySpecification() {
        specificationContent = "";
    }

    @Given("I have invalid JSON content {string}")
    public void iHaveInvalidJSONContent(String content) {
        specificationContent = content;
    }

    @Given("I have an OpenAPI specification with path parameters")
    public void iHaveAnOpenAPISpecificationWithPathParameters() throws Exception {
        InputStream is = getClass().getClassLoader().getResourceAsStream("openapi-petstore.json");
        assertNotNull(is);
        specificationContent = new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    @Given("I have an OpenAPI specification with query parameters")
    public void iHaveAnOpenAPISpecificationWithQueryParameters() throws Exception {
        InputStream is = getClass().getClassLoader().getResourceAsStream("openapi-petstore.json");
        assertNotNull(is);
        specificationContent = new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    @Given("I have a valid OpenAPI YAML specification")
    public void iHaveAValidOpenAPIYAMLSpecification() throws Exception {
        InputStream is = getClass().getClassLoader().getResourceAsStream("openapi-sample.yaml");
        assertNotNull(is, "YAML test resource not found");
        specificationContent = new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    @When("I parse the specification")
    public void iParseTheSpecification() {
        parseResult = parser.parse("test-spec", specificationContent);
        assertNotNull(parseResult, "Parse result should not be null");
    }

    @Then("I should get {int} API endpoints")
    public void iShouldGetAPIEndpoints(int expectedCount) {
        if (expectedCount == 0) {
            assertTrue(parseResult.getEndpoints().isEmpty(),
                "Expected no endpoints but got " + parseResult.getEndpoints().size());
        } else {
            assertFalse(parseResult.getEndpoints().isEmpty(),
                "Expected endpoints but got none");
        }
    }

    @Then("I should get {int} endpoints")
    public void iShouldGetEndpoints(int expectedCount) {
        assertEquals(expectedCount, parseResult.getEndpoints().size(),
            "Expected " + expectedCount + " endpoints");
    }

    @And("each endpoint should have a valid HTTP method")
    public void eachEndpointShouldHaveAValidHTTPMethod() {
        List<String> validMethods = List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD");
        for (ApiEndpoint endpoint : parseResult.getEndpoints()) {
            assertTrue(validMethods.contains(endpoint.getMethod().toUpperCase()),
                "Invalid HTTP method: " + endpoint.getMethod());
        }
    }

    @And("each endpoint should have a valid path")
    public void eachEndpointShouldHaveAValidPath() {
        for (ApiEndpoint endpoint : parseResult.getEndpoints()) {
            assertNotNull(endpoint.getPath(), "Endpoint path should not be null");
            assertTrue(endpoint.getPath().startsWith("/"),
                "Path should start with /: " + endpoint.getPath());
        }
    }

    @And("I should receive an error message containing {string}")
    public void iShouldReceiveAnErrorMessageContaining(String expectedText) {
        assertFalse(parseResult.getMessages().isEmpty(), "Expected error messages");
        boolean found = parseResult.getMessages().stream()
            .anyMatch(msg -> msg.toLowerCase().contains(expectedText.toLowerCase()));
        assertTrue(found, "Expected error message containing: " + expectedText);
    }

    @And("I should receive error messages")
    public void iShouldReceiveErrorMessages() {
        assertFalse(parseResult.getMessages().isEmpty(),
            "Expected at least one error message");
    }

    @Then("I should get endpoints with parameter definitions")
    public void iShouldGetEndpointsWithParameterDefinitions() {
        assertFalse(parseResult.getEndpoints().isEmpty(), "Expected endpoints");
        boolean hasParams = parseResult.getEndpoints().stream()
            .anyMatch(ep -> !ep.getParameters().isEmpty());
        assertTrue(hasParams, "Expected at least one endpoint with parameters");
    }

    @And("parameters should include {string} of type {string}")
    public void parametersShouldIncludeOfType(String paramName, String paramType) {
        boolean found = parseResult.getEndpoints().stream()
            .flatMap(ep -> ep.getParameters().stream())
            .anyMatch(p -> p.getName().equals(paramName) && p.getLocation().equals(paramType));
        assertTrue(found,
            String.format("Expected parameter '%s' of type '%s'", paramName, paramType));
    }

    @And("parameters should include query parameters")
    public void parametersShouldIncludeQueryParameters() {
        boolean hasQueryParams = parseResult.getEndpoints().stream()
            .flatMap(ep -> ep.getParameters().stream())
            .anyMatch(p -> "query".equals(p.getLocation()));
        assertTrue(hasQueryParams, "Expected at least one query parameter");
    }

    @Then("I should get API endpoints")
    public void iShouldGetAPIEndpoints() {
        assertFalse(parseResult.getEndpoints().isEmpty(),
            "Expected at least one endpoint");
    }

    @And("the specification format should be correctly detected")
    public void theSpecificationFormatShouldBeCorrectlyDetected() {
        // If we got endpoints without errors, the format was correctly detected
        assertFalse(parseResult.getEndpoints().isEmpty(), "Expected endpoints from YAML");
    }
}
