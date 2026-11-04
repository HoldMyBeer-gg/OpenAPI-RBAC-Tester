package burp.openapirbactester;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MontoyaPrefsBackendTest {

    @Test
    void get_delegatesToPreferencesGetString() {
        Preferences prefs = mock(Preferences.class);
        when(prefs.getString("k")).thenReturn("v");
        var backend = new MontoyaPrefsBackend(prefs);
        assertEquals("v", backend.get("k"));
        verify(prefs).getString("k");
    }

    @Test
    void put_delegatesToPreferencesSetString() {
        Preferences prefs = mock(Preferences.class);
        var backend = new MontoyaPrefsBackend(prefs);
        backend.put("k", "v");
        verify(prefs).setString("k", "v");
    }

    @Test
    void remove_delegatesToPreferencesDeleteString() {
        Preferences prefs = mock(Preferences.class);
        var backend = new MontoyaPrefsBackend(prefs);
        backend.remove("k");
        verify(prefs).deleteString("k");
    }

    @Test
    void keys_returnsDefensiveCopyOfStringKeys() {
        Preferences prefs = mock(Preferences.class);
        Set<String> underlying = new LinkedHashSet<>();
        underlying.add("a");
        underlying.add("b");
        when(prefs.stringKeys()).thenReturn(underlying);

        var backend = new MontoyaPrefsBackend(prefs);
        Set<String> keys = backend.keys();
        assertEquals(2, keys.size());
        assertTrue(keys.contains("a"));
        assertTrue(keys.contains("b"));

        // Mutating the returned set must not affect the underlying prefs.
        keys.clear();
        assertEquals(2, underlying.size());
    }
}
