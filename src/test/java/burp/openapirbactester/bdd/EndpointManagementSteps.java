package burp.openapirbactester.bdd;

import burp.openapirbactester.ApiEndpoint;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Step definitions for API endpoint management BDD scenarios.
 */
public class EndpointManagementSteps {

    private ApiEndpoint endpoint;
    private ApiEndpoint endpoint2;
    private String method;
    private String path;
    private List<ApiEndpoint.ParameterInfo> parameters;
    private boolean comparisonResult;

    public EndpointManagementSteps() {
        this.parameters = new ArrayList<>();
    }

    @Given("I want to create an endpoint")
    public void iWantToCreateAnEndpoint() {
        // Setup - no action needed
    }

    @When("I create an endpoint with method {string} and path {string}")
    public void iCreateAnEndpointWithMethodAndPath(String method, String path) {
        this.method = method;
        this.path = path;
        endpoint = new ApiEndpoint(
            1,
            "https",
            method,
            "https://api.test.com",
            path,
            List.of(),
            ""
        );
    }

    @Then("the endpoint should have a unique ID")
    public void theEndpointShouldHaveAUniqueID() {
        assertNotNull(endpoint, "Endpoint should be created");
        assertTrue(endpoint.getIndex() > 0, "Endpoint should have a valid ID");
    }

    @And("the endpoint should store the HTTP method")
    public void theEndpointShouldStoreTheHTTPMethod() {
        assertEquals(method, endpoint.getMethod(),
            "Endpoint should store the correct HTTP method");
    }

    @And("the endpoint should store the path")
    public void theEndpointShouldStoreThePath() {
        assertEquals(path, endpoint.getPath(),
            "Endpoint should store the correct path");
    }

    @Given("I create an endpoint with parameters")
    public void iCreateAnEndpointWithParameters() {
        parameters = new ArrayList<>();
        endpoint = new ApiEndpoint(
            1,
            "https",
            "GET",
            "https://api.test.com",
            "/users/{userId}",
            parameters,
            ""
        );
    }

    @When("I add a parameter {string} of type {string}")
    public void iAddAParameterOfType(String paramName, String paramType) {
        parameters.add(new ApiEndpoint.ParameterInfo(paramName, paramType, ""));
        // Recreate endpoint with updated parameters
        endpoint = new ApiEndpoint(
            1,
            "https",
            "GET",
            "https://api.test.com",
            "/users/{userId}",
            parameters,
            ""
        );
    }

    @Then("the endpoint should contain {int} parameters")
    public void theEndpointShouldContainParameters(int expectedCount) {
        assertEquals(expectedCount, endpoint.getParameters().size(),
            "Expected " + expectedCount + " parameters");
    }

    @And("I should be able to retrieve parameter details")
    public void iShouldBeAbleToRetrieveParameterDetails() {
        assertFalse(endpoint.getParameters().isEmpty(),
            "Should have parameters to retrieve");
        for (var param : endpoint.getParameters()) {
            assertNotNull(param.getName(), "Parameter name should not be null");
            assertNotNull(param.getLocation(), "Parameter type should not be null");
        }
    }

    @Given("I have two endpoints with the same method and path")
    public void iHaveTwoEndpointsWithTheSameMethodAndPath() {
        endpoint = new ApiEndpoint(
            1,
            "https",
            "GET",
            "https://api.test.com",
            "/users",
            List.of(),
            ""
        );
        endpoint2 = new ApiEndpoint(
            2,  // Different ID
            "https",
            "GET",
            "https://api.test.com",
            "/users",
            List.of(),
            ""
        );
    }

    @Given("I have a first endpoint with method {string} and path {string}")
    public void iHaveAFirstEndpointWithMethodAndPath(String method, String path) {
        endpoint = new ApiEndpoint(
            1,
            "https",
            method,
            "https://api.test.com",
            path,
            List.of(),
            ""
        );
    }

    @And("I have a second endpoint with method {string} and path {string}")
    public void iHaveASecondEndpointWithMethodAndPath(String method, String path) {
        endpoint2 = new ApiEndpoint(
            2,
            "https",
            method,
            "https://api.test.com",
            path,
            List.of(),
            ""
        );
    }

    @When("I compare the endpoints")
    public void iCompareTheEndpoints() {
        comparisonResult = endpoint.equals(endpoint2);
    }

    @Then("they should have matching methods and paths")
    public void theyShouldHaveMatchingMethodsAndPaths() {
        assertEquals(endpoint.getMethod(), endpoint2.getMethod(),
            "Endpoints should have the same method");
        assertEquals(endpoint.getPath(), endpoint2.getPath(),
            "Endpoints should have the same path");
    }

    @Then("they should have different methods")
    public void theyShouldHaveDifferentMethods() {
        assertNotEquals(endpoint.getMethod(), endpoint2.getMethod(),
            "Endpoints should have different methods");
    }
}
