package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetworkHintsTest {

    private static final String PROJECT_SOCKS_ON = """
            {"project_options":{"connections":{
              "socks_proxy":{"dns_over_socks":false,"host":"127.0.0.1","port":9119,"use_proxy":true,"use_user_options":false},
              "upstream_proxy":{"servers":[],"use_user_options":false}}}}""";

    private static final String PROJECT_ALL_OFF = """
            {"project_options":{"connections":{
              "socks_proxy":{"host":"","port":0,"use_proxy":false,"use_user_options":false},
              "upstream_proxy":{"servers":[],"use_user_options":false}}}}""";

    private static final String PROJECT_DEFERS_TO_USER = """
            {"project_options":{"connections":{
              "socks_proxy":{"use_proxy":false,"use_user_options":true},
              "upstream_proxy":{"servers":[],"use_user_options":true}}}}""";

    private static final String USER_SOCKS_ON = """
            {"user_options":{"connections":{
              "socks_proxy":{"host":"10.0.0.5","port":1080,"use_proxy":true},
              "upstream_proxy":{"servers":[]}}}}""";

    private static final String USER_UPSTREAM_ON = """
            {"user_options":{"connections":{
              "socks_proxy":{"use_proxy":false},
              "upstream_proxy":{"servers":[
                {"destination_host":"*","enabled":true,"proxy_host":"corp-proxy","proxy_port":3128},
                {"destination_host":"*.old","enabled":false,"proxy_host":"dead","proxy_port":1}]}}}}""";

    @Test
    void projectSocksEnabled_namesTheProxy() {
        String hint = NetworkHints.describe(PROJECT_SOCKS_ON, USER_UPSTREAM_ON);
        assertNotNull(hint);
        assertTrue(hint.contains("SOCKS proxy at 127.0.0.1:9119"), hint);
        assertTrue(hint.contains("Settings"), "should point at where to fix it: " + hint);
    }

    @Test
    void nothingEnabled_returnsNull() {
        assertNull(NetworkHints.describe(PROJECT_ALL_OFF, "{}"));
    }

    @Test
    void projectDefersToUser_userSocksEnabled_namesUserProxy() {
        String hint = NetworkHints.describe(PROJECT_DEFERS_TO_USER, USER_SOCKS_ON);
        assertNotNull(hint);
        assertTrue(hint.contains("SOCKS proxy at 10.0.0.5:1080"), hint);
    }

    @Test
    void projectDefersToUser_userUpstreamEnabled_namesOnlyEnabledServers() {
        String hint = NetworkHints.describe(PROJECT_DEFERS_TO_USER, USER_UPSTREAM_ON);
        assertNotNull(hint);
        assertTrue(hint.contains("upstream proxy corp-proxy:3128"), hint);
        assertFalse(hint.contains("dead"), hint);
    }

    @Test
    void projectDefersToUser_butUserOptionsUnreadable_returnsNull_notStaleProjectValues() {
        // Burp keeps the old host/port in the project JSON after switching to user options.
        String staleProject = """
                {"project_options":{"connections":{
                  "socks_proxy":{"host":"10.0.0.5","port":1080,"use_proxy":true,"use_user_options":true},
                  "upstream_proxy":{"servers":[{"enabled":true,"proxy_host":"old","proxy_port":1,"destination_host":"*"}],"use_user_options":true}}}}""";
        assertNull(NetworkHints.describe(staleProject, null));
        assertNull(NetworkHints.describe(staleProject, "not json"));
    }

    @Test
    void garbageOrNull_returnsNull() {
        assertNull(NetworkHints.describe("not json", null));
        assertNull(NetworkHints.describe(null, null));
        assertNull(NetworkHints.describe("", ""));
    }
}
