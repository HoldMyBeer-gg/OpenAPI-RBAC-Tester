package burp.openapirbactester.bdd;

import burp.openapirbactester.ApiEndpoint;
import burp.openapirbactester.RequestGenerator;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Step definitions for HTTP request generation BDD scenarios.
 */
public class RequestGenerationSteps {

    private RequestGenerator generator;
    private ApiEndpoint endpoint;
    private String method;
    private String path;
    private String baseUrl;
    private String overrideUrl;
    private List<ApiEndpoint.ParameterInfo> parameters;
    private byte[] generatedRequest;

    public RequestGenerationSteps() {
        this.generator = new RequestGenerator();
        this.parameters = new ArrayList<>();
    }

    @Given("I have an endpoint with method {string} and path {string}")
    public void iHaveAnEndpointWithMethodAndPath(String method, String path) {
        this.method = method;
        this.path = path;
    }

    @And("the endpoint base URL is {string}")
    public void theEndpointBaseURLIs(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    @Given("I have an endpoint with path {string}")
    public void iHaveAnEndpointWithPath(String path) {
        this.method = "GET";
        this.path = path;
        this.baseUrl = "https://api.test.com";
    }

    @And("the endpoint has a path parameter {string} with value {string}")
    public void theEndpointHasAPathParameterWithValue(String paramName, String paramValue) {
        parameters.add(new ApiEndpoint.ParameterInfo(paramName, "path", paramValue));
    }

    @Given("I have an endpoint with base URL {string}")
    public void iHaveAnEndpointWithBaseURL(String baseUrl) {
        this.method = "GET";
        this.path = "/users";
        this.baseUrl = baseUrl;
    }

    @And("I want to override the base URL with {string}")
    public void iWantToOverrideTheBaseURLWith(String overrideUrl) {
        this.overrideUrl = overrideUrl;
    }

    @Given("I have an endpoint with query parameters")
    public void iHaveAnEndpointWithQueryParameters() {
        this.method = "GET";
        this.path = "/users";
        this.baseUrl = "https://api.test.com";
    }

    @And("the query parameter {string} has value {string}")
    public void theQueryParameterHasValue(String paramName, String paramValue) {
        parameters.add(new ApiEndpoint.ParameterInfo(paramName, "query", paramValue));
    }

    @When("I generate an HTTP request")
    public void iGenerateAnHTTPRequest() {
        // Create the endpoint with all configured parameters
        endpoint = new ApiEndpoint(
            1,
            baseUrl.startsWith("https") ? "https" : "http",
            method,
            baseUrl,
            path,
            parameters,
            ""
        );

        generatedRequest = generator.buildRequestBytes(endpoint, overrideUrl);
        assertNotNull(generatedRequest, "Generated request should not be null");
    }

    @Then("the request should contain {string}")
    public void theRequestShouldContain(String expectedContent) {
        String request = new String(generatedRequest, StandardCharsets.UTF_8);
        assertTrue(request.contains(expectedContent),
            "Expected request to contain: " + expectedContent + "\nActual request:\n" + request);
    }

    @And("the request should contain a JSON body")
    public void theRequestShouldContainAJSONBody() {
        String request = new String(generatedRequest, StandardCharsets.UTF_8);
        assertTrue(request.contains("{") && request.contains("}"),
            "Expected request to contain JSON body");
    }

    @Then("the request path should contain {string}")
    public void theRequestPathShouldContain(String expectedPathContent) {
        String request = new String(generatedRequest, StandardCharsets.UTF_8);
        assertTrue(request.contains(expectedPathContent),
            "Expected request path to contain: " + expectedPathContent);
    }

    @And("the path should not contain any braces")
    public void thePathShouldNotContainAnyBraces() {
        String request = new String(generatedRequest, StandardCharsets.UTF_8);
        String[] lines = request.split("\n");
        if (lines.length > 0) {
            String requestLine = lines[0];
            assertFalse(requestLine.contains("{") || requestLine.contains("}"),
                "Request path should not contain braces: " + requestLine);
        }
    }

    @And("all curly braces should be replaced with default values")
    public void allCurlyBracesShouldBeReplacedWithDefaultValues() {
        String request = new String(generatedRequest, StandardCharsets.UTF_8);
        String[] lines = request.split("\n");
        if (lines.length > 0) {
            String requestLine = lines[0];
            assertFalse(requestLine.contains("{") || requestLine.contains("}"),
                "All parameters should be substituted: " + requestLine);
        }
    }
}
