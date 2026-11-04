package burp.openapirbactester;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns Burp's exported connection settings into a one-line explanation of why a request
 * may have produced no response. Burp routes extension traffic through the same SOCKS /
 * upstream proxy settings as everything else, and a stale proxy entry fails silently from
 * an extension's point of view: {@code sendRequest} just returns a null response.
 * <p>
 * Pure function over the JSON strings from
 * {@code api.burpSuite().exportProjectOptionsAsJson("project_options.connections")} and
 * {@code exportUserOptionsAsJson("user_options.connections")}, so it is testable without Burp.
 */
final class NetworkHints {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String WHERE = " (Settings → Network → Connections)";

    private NetworkHints() {}

    /**
     * @return a hint naming the active SOCKS and/or upstream proxies, or {@code null} when
     *         none is enabled or the settings could not be read.
     */
    static String describe(String projectOptionsJson, String userOptionsJson) {
        JsonNode project = connections(projectOptionsJson, "project_options");
        JsonNode user = connections(userOptionsJson, "user_options");
        if (project == null && user == null) return null;

        List<String> active = new ArrayList<>();

        JsonNode socks = pick(project, user, "socks_proxy");
        if (socks != null && socks.path("use_proxy").asBoolean(false)) {
            active.add("SOCKS proxy at " + socks.path("host").asText("") + ":" + socks.path("port").asInt(0));
        }

        JsonNode upstream = pick(project, user, "upstream_proxy");
        if (upstream != null) {
            for (JsonNode server : upstream.path("servers")) {
                if (server.path("enabled").asBoolean(false)) {
                    active.add("upstream proxy " + server.path("proxy_host").asText("")
                            + ":" + server.path("proxy_port").asInt(0)
                            + " for " + server.path("destination_host").asText("*"));
                }
            }
        }

        if (active.isEmpty()) return null;
        return "Burp is routing requests through " + String.join(" and ", active) + WHERE
                + ". Check that it is running, or disable it.";
    }

    /** The {@code connections} object under the given root key, or null if absent/unparseable. */
    private static JsonNode connections(String json, String rootKey) {
        if (json == null || json.isBlank()) return null;
        try {
            JsonNode node = MAPPER.readTree(json).path(rootKey).path("connections");
            return node.isMissingNode() ? null : node;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Project settings win unless they say {@code use_user_options}, in which case the user
     * settings apply. When the project defers and the user section is unreadable the answer
     * is unknown, not the project's stale values: Burp keeps the old host/port in the project
     * JSON after the switch, and naming them would send the user to debug the wrong proxy.
     */
    private static JsonNode pick(JsonNode project, JsonNode user, String section) {
        JsonNode fromProject = project != null ? project.path(section) : null;
        JsonNode fromUser = user != null ? user.path(section) : null;
        boolean haveUser = fromUser != null && !fromUser.isMissingNode();
        if (fromProject != null && !fromProject.isMissingNode()) {
            if (fromProject.path("use_user_options").asBoolean(false)) {
                return haveUser ? fromUser : null;
            }
            return fromProject;
        }
        return haveUser ? fromUser : null;
    }
}
