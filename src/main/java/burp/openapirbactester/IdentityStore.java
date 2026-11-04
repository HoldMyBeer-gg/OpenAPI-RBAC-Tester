package burp.openapirbactester;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages the ordered list of named identities and the index of the active one.
 * Persists to a {@link PrefsBackend} (a thin wrapper over Montoya's
 * {@link burp.api.montoya.persistence.Preferences}, or an in-memory fake in
 * tests) using numbered string keys:
 *
 * <pre>
 *   rbactester.identity.count  -> "3"
 *   rbactester.identity.active -> "1"
 *   rbactester.identity.0      -> serialised identity
 *   rbactester.identity.1      -> serialised identity
 *   rbactester.identity.2      -> serialised identity
 * </pre>
 *
 * Always contains at least one identity ("Default" if none exist in storage).
 * Java Preferences has an 8KB per-value limit; one identity per key keeps us
 * well under it even for multi-JWT, multi-header setups.
 */
public class IdentityStore {

    static final String PREFIX = "rbactester.identity.";
    static final String KEY_COUNT = PREFIX + "count";
    static final String KEY_ACTIVE = PREFIX + "active";

    /**
     * Thin persistence abstraction. The Montoya adapter is thread-safe for single-JVM
     * usage; no additional synchronisation is needed in IdentityStore as long as all
     * mutations happen on the EDT (which they do here).
     */
    public interface PrefsBackend {
        String get(String key);
        void put(String key, String value);
        void remove(String key);
        Set<String> keys();
    }

    private final PrefsBackend prefs;
    private final List<Identity> identities = new ArrayList<>();
    private int activeIndex = 0;

    public IdentityStore(PrefsBackend prefs) {
        this.prefs = prefs;
        load();
    }

    public List<Identity> identities() {
        return Collections.unmodifiableList(identities);
    }

    public int size() {
        return identities.size();
    }

    public int activeIndex() {
        return activeIndex;
    }

    public Identity active() {
        return identities.get(activeIndex);
    }

    public Identity get(int index) {
        return identities.get(index);
    }

    /** Switches the active identity. Throws if index is out of range. */
    public void setActive(int index) {
        if (index < 0 || index >= identities.size()) {
            throw new IndexOutOfBoundsException("identity index " + index + " out of range [0, " + identities.size() + ")");
        }
        activeIndex = index;
        persist();
    }

    /**
     * Replaces the active identity's payload (keeps the name unless the caller
     * explicitly renames). Used when the user edits fields — we snapshot the
     * form into the active slot.
     */
    public void replaceActive(Identity updated) {
        identities.set(activeIndex, updated);
        persist();
    }

    /** Adds a new identity and makes it active. Rejects duplicate names. */
    public Identity add(Identity identity) {
        assertUniqueName(identity.name(), -1);
        identities.add(identity);
        activeIndex = identities.size() - 1;
        persist();
        return identity;
    }

    /**
     * Removes the identity at the given index. Refuses to remove the last remaining
     * identity — the invariant is "at least one always exists". Adjusts activeIndex
     * so it remains in range.
     */
    public void remove(int index) {
        if (identities.size() <= 1) {
            throw new IllegalStateException("Cannot remove the last remaining identity");
        }
        if (index < 0 || index >= identities.size()) {
            throw new IndexOutOfBoundsException("identity index " + index);
        }
        identities.remove(index);
        if (activeIndex >= identities.size()) activeIndex = identities.size() - 1;
        else if (activeIndex > index) activeIndex--;
        persist();
    }

    /** Renames the identity at the given index. Rejects names that collide with others. */
    public void rename(int index, String newName) {
        if (index < 0 || index >= identities.size()) {
            throw new IndexOutOfBoundsException("identity index " + index);
        }
        assertUniqueName(newName, index);
        identities.set(index, identities.get(index).withName(newName));
        persist();
    }

    /** Writes current state to prefs, wiping stale keys from any previous session. */
    void persist() {
        Set<String> toRemove = new HashSet<>();
        for (String k : prefs.keys()) {
            if (k.startsWith(PREFIX)) toRemove.add(k);
        }
        for (String k : toRemove) prefs.remove(k);
        prefs.put(KEY_COUNT, Integer.toString(identities.size()));
        prefs.put(KEY_ACTIVE, Integer.toString(activeIndex));
        for (int i = 0; i < identities.size(); i++) {
            prefs.put(PREFIX + i, identities.get(i).serialise());
        }
    }

    private void load() {
        int count = parseIntOrDefault(prefs.get(KEY_COUNT), -1);
        if (count <= 0) {
            identities.add(Identity.empty("Default"));
            activeIndex = 0;
            persist();
            return;
        }
        for (int i = 0; i < count; i++) {
            String raw = prefs.get(PREFIX + i);
            if (raw == null || raw.isBlank()) continue;
            try {
                identities.add(Identity.deserialise(raw));
            } catch (Exception ignored) {
                // Skip corrupted entries rather than failing to load the whole panel.
            }
        }
        if (identities.isEmpty()) {
            identities.add(Identity.empty("Default"));
            activeIndex = 0;
            persist();
            return;
        }
        int active = parseIntOrDefault(prefs.get(KEY_ACTIVE), 0);
        activeIndex = Math.max(0, Math.min(active, identities.size() - 1));
    }

    private void assertUniqueName(String name, int ignoreIndex) {
        String trimmed = name == null ? "" : name.trim();
        if (trimmed.isEmpty()) throw new IllegalArgumentException("Identity name must not be blank");
        for (int i = 0; i < identities.size(); i++) {
            if (i == ignoreIndex) continue;
            if (identities.get(i).name().equals(trimmed)) {
                throw new IllegalArgumentException("Identity name already exists: " + trimmed);
            }
        }
    }

    private static int parseIntOrDefault(String s, int fallback) {
        if (s == null) return fallback;
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return fallback; }
    }
}
