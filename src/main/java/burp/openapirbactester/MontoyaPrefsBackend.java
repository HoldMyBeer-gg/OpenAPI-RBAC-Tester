package burp.openapirbactester;

import burp.api.montoya.persistence.Preferences;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Thin adapter exposing Montoya's {@link Preferences} as an
 * {@link IdentityStore.PrefsBackend}. Isolated so {@link IdentityStore} can be
 * unit-tested with an in-memory fake instead of the real Burp store.
 */
public class MontoyaPrefsBackend implements IdentityStore.PrefsBackend {

    private final Preferences preferences;

    public MontoyaPrefsBackend(Preferences preferences) {
        this.preferences = preferences;
    }

    @Override
    public String get(String key) {
        return preferences.getString(key);
    }

    @Override
    public void put(String key, String value) {
        preferences.setString(key, value);
    }

    @Override
    public void remove(String key) {
        preferences.deleteString(key);
    }

    @Override
    public Set<String> keys() {
        // Defensive copy — Montoya's keySet may or may not be a live view.
        return new LinkedHashSet<>(preferences.stringKeys());
    }
}
