# BDD Testing with Cucumber 🥒

Your OpenAPI-RBAC-Tester Burp Suite extension now has **BDD (Behavior-Driven Development) testing** set up with Cucumber!

## What Was Added

### 1. Dependencies
- **Cucumber Java** - Core BDD framework
- **Cucumber JUnit Platform Engine** - Integration with JUnit 5
- **JUnit Platform Suite** - Test runner support

### 2. Feature Files (Gherkin Scenarios)
Located in `src/test/resources/features/`:

- **openapi-parsing.feature** - Scenarios for parsing OpenAPI specifications
- **request-generation.feature** - Scenarios for generating HTTP requests
- **endpoint-management.feature** - Scenarios for managing API endpoints

### 3. Step Definitions
Located in `src/test/java/burp/openapirbactester/bdd/`:

- **OpenAPIParsingSteps.java** - Implements parsing scenarios
- **RequestGenerationSteps.java** - Implements request generation scenarios
- **EndpointManagementSteps.java** - Implements endpoint management scenarios

### 4. Test Runner
- **CucumberTestRunner.java** - Executes all BDD scenarios

## Running BDD Tests

### Run all BDD tests:
```bash
./gradlew test --tests "burp.openapirbactester.bdd.CucumberTestRunner"
```

### Run all tests (BDD + unit tests):
```bash
./gradlew test
```

### View test results:
- **HTML Report**: `build/reports/cucumber/cucumber.html`
- **JSON Report**: `build/reports/cucumber/cucumber.json`
- **JUnit Report**: `build/reports/tests/test/index.html`

## Example BDD Scenario

```gherkin
Feature: OpenAPI Specification Parsing
  As a security tester
  I want to parse OpenAPI specifications
  So that I can identify and test API endpoints in Burp Suite

  Scenario: Parse a valid OpenAPI 3.0 specification
    Given I have a valid OpenAPI specification with 3 endpoints
    When I parse the specification
    Then I should get 3 API endpoints
    And each endpoint should have a valid HTTP method
    And each endpoint should have a valid path
```

## Benefits

✅ **Readable Tests** - Business stakeholders can understand test scenarios
✅ **Living Documentation** - Feature files document the system's behavior
✅ **Test Coverage** - 16 BDD scenarios covering key functionality
✅ **CI/CD Ready** - Integrates with your existing Gradle build
✅ **HTML Reports** - Beautiful, detailed test reports

## Adding New Scenarios

1. **Create a feature file** in `src/test/resources/features/your-feature.feature`
2. **Write scenarios** using Given-When-Then format
3. **Implement step definitions** in `src/test/java/burp/openapirbactester/bdd/`
4. **Run tests** to verify

## Current Test Coverage

- ✅ OpenAPI parsing (6 scenarios)
- ✅ HTTP request generation (6 scenarios)
- ✅ Endpoint management (4 scenarios)

**Total: 16 BDD scenarios** running alongside your existing JUnit unit tests!

---

*BDD testing complements your existing unit tests and provides a higher-level view of system behavior.*
