package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Keeps BappManifest.bmf in step with build.gradle and the name Burp displays. PortSwigger
 * builds from the manifest's EntryPoint, so a version bump that leaves it stale breaks their build.
 */
class BappManifestTest {

    private static Map<String, String> manifest() throws IOException {
        Map<String, String> fields = new HashMap<>();
        for (String line : Files.readAllLines(Path.of("BappManifest.bmf"), StandardCharsets.UTF_8)) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                fields.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
            }
        }
        return fields;
    }

    private static String gradleVersion() throws IOException {
        String gradle = Files.readString(Path.of("build.gradle"), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("(?m)^version\\s*=\\s*'([^']+)'").matcher(gradle);
        assertTrue(m.find(), "build.gradle has no version line");
        return m.group(1);
    }

    @Test
    void entryPointMatchesTheJarTheBuildProduces() throws IOException {
        assertEquals("build/libs/OpenAPI-RBAC-Tester-" + gradleVersion() + ".jar",
                manifest().get("EntryPoint"));
    }

    @Test
    void screenVersionMatchesBuildVersion() throws IOException {
        assertEquals(gradleVersion(), manifest().get("ScreenVersion"));
    }

    @Test
    void manifestNameMatchesDisplayName() throws IOException {
        assertEquals("OpenAPI RBAC Tester", ExtensionInfo.DISPLAY_NAME);
        assertEquals(ExtensionInfo.DISPLAY_NAME, manifest().get("Name"));
    }
}
