package burp.openapirbactester;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class IdentityStoreTest {

    /** In-memory fake of Montoya Preferences for deterministic tests. */
    static class FakePrefs implements IdentityStore.PrefsBackend {
        final Map<String, String> data = new LinkedHashMap<>();

        @Override public String get(String key) { return data.get(key); }
        @Override public void put(String key, String value) { data.put(key, value); }
        @Override public void remove(String key) { data.remove(key); }
        @Override public Set<String> keys() { return new LinkedHashSet<>(data.keySet()); }
    }

    private FakePrefs prefs;

    @BeforeEach
    void setUp() {
        prefs = new FakePrefs();
    }

    @Test
    void emptyStore_seedsWithDefault() {
        var store = new IdentityStore(prefs);
        assertEquals(1, store.size());
        assertEquals("Default", store.active().name());
        assertEquals(0, store.activeIndex());
        assertEquals("1", prefs.get(IdentityStore.KEY_COUNT), "seed should persist");
    }

    @Test
    void addIdentity_becomesActive() {
        var store = new IdentityStore(prefs);
        store.add(Identity.empty("admin"));
        assertEquals(2, store.size());
        assertEquals("admin", store.active().name());
        assertEquals(1, store.activeIndex());
    }

    @Test
    void add_duplicateName_rejected() {
        var store = new IdentityStore(prefs);
        store.add(Identity.empty("admin"));
        assertThrows(IllegalArgumentException.class, () -> store.add(Identity.empty("admin")));
    }

    @Test
    void add_blankName_rejectedAtConstruction() {
        assertThrows(IllegalArgumentException.class, () -> Identity.empty(""));
    }

    @Test
    void persist_restoresAcrossNewInstances() {
        var store1 = new IdentityStore(prefs);
        store1.add(Identity.empty("user"));
        store1.add(Identity.empty("admin"));
        store1.setActive(1);

        // Construct a new store against the same prefs — simulates Burp restart.
        var store2 = new IdentityStore(prefs);
        assertEquals(3, store2.size());
        assertEquals("Default", store2.get(0).name());
        assertEquals("user", store2.get(1).name());
        assertEquals("admin", store2.get(2).name());
        assertEquals(1, store2.activeIndex());
        assertEquals("user", store2.active().name());
    }

    @Test
    void setActive_outOfRange_throws() {
        var store = new IdentityStore(prefs);
        assertThrows(IndexOutOfBoundsException.class, () -> store.setActive(5));
        assertThrows(IndexOutOfBoundsException.class, () -> store.setActive(-1));
    }

    @Test
    void replaceActive_updatesCurrentSlot() {
        var store = new IdentityStore(prefs);
        var updated = new Identity("Default",
                new AuthConfig("eyJfresh", null, null, null, null, null),
                "https://api.example.com");
        store.replaceActive(updated);
        assertEquals("eyJfresh", store.active().authConfig().bearerToken());
        assertEquals("https://api.example.com", store.active().baseUrlOverride());
    }

    @Test
    void remove_lastIdentity_refused() {
        var store = new IdentityStore(prefs);
        assertThrows(IllegalStateException.class, () -> store.remove(0));
    }

    @Test
    void remove_fromMiddle_adjustsActiveIndex() {
        var store = new IdentityStore(prefs);
        store.add(Identity.empty("A"));
        store.add(Identity.empty("B"));
        store.add(Identity.empty("C"));
        assertEquals(4, store.size());
        store.setActive(3); // "C"
        store.remove(1); // remove "A"
        assertEquals(3, store.size());
        assertEquals(2, store.activeIndex(), "active should shift left when a prior entry is removed");
        assertEquals("C", store.active().name());
    }

    @Test
    void remove_activeIdentity_picksNextAvailable() {
        var store = new IdentityStore(prefs);
        store.add(Identity.empty("A"));
        store.setActive(1); // active is "A"
        store.remove(1);
        assertEquals(1, store.size());
        assertEquals(0, store.activeIndex());
        assertEquals("Default", store.active().name());
    }

    @Test
    void remove_outOfRange_throws() {
        var store = new IdentityStore(prefs);
        store.add(Identity.empty("other"));
        assertThrows(IndexOutOfBoundsException.class, () -> store.remove(5));
        assertThrows(IndexOutOfBoundsException.class, () -> store.remove(-1));
    }

    @Test
    void rename_succeedsWithUniqueName() {
        var store = new IdentityStore(prefs);
        store.rename(0, "Primary");
        assertEquals("Primary", store.active().name());
    }

    @Test
    void rename_duplicateName_rejected() {
        var store = new IdentityStore(prefs);
        store.add(Identity.empty("admin"));
        assertThrows(IllegalArgumentException.class, () -> store.rename(0, "admin"));
    }

    @Test
    void rename_sameName_allowed() {
        var store = new IdentityStore(prefs);
        store.rename(0, "Default"); // no-op rename; must not trip the uniqueness check
        assertEquals("Default", store.active().name());
    }

    @Test
    void rename_blankName_rejected() {
        var store = new IdentityStore(prefs);
        assertThrows(IllegalArgumentException.class, () -> store.rename(0, "   "));
    }

    @Test
    void rename_outOfRange_throws() {
        var store = new IdentityStore(prefs);
        assertThrows(IndexOutOfBoundsException.class, () -> store.rename(5, "whatever"));
    }

    @Test
    void identities_listIsUnmodifiable() {
        var store = new IdentityStore(prefs);
        assertThrows(UnsupportedOperationException.class, () -> store.identities().add(Identity.empty("hack")));
    }

    @Test
    void corruptedEntry_skippedDuringLoad() {
        prefs.put(IdentityStore.KEY_COUNT, "3");
        prefs.put(IdentityStore.PREFIX + "0", Identity.empty("valid").serialise());
        prefs.put(IdentityStore.PREFIX + "1", "this is not a valid serialised identity &&&&&");
        prefs.put(IdentityStore.PREFIX + "2", Identity.empty("also-valid").serialise());
        prefs.put(IdentityStore.KEY_ACTIVE, "0");

        var store = new IdentityStore(prefs);
        // Only the two valid entries survive; active clamped into range.
        assertEquals(2, store.size());
        assertEquals("valid", store.get(0).name());
        assertEquals("also-valid", store.get(1).name());
    }

    @Test
    void allEntriesCorrupted_fallsBackToDefault() {
        prefs.put(IdentityStore.KEY_COUNT, "2");
        prefs.put(IdentityStore.PREFIX + "0", "&corrupted&");
        prefs.put(IdentityStore.PREFIX + "1", "");

        var store = new IdentityStore(prefs);
        assertEquals(1, store.size());
        assertEquals("Default", store.active().name());
    }

    @Test
    void missingCountKey_seedsDefault() {
        // No rbactester.identity.* keys at all: this is the first-ever run case.
        var store = new IdentityStore(prefs);
        assertEquals("Default", store.active().name());
    }

    @Test
    void activeIndexOutOfBounds_clampedOnLoad() {
        var seedStore = new IdentityStore(prefs);
        seedStore.add(Identity.empty("a"));
        // Manually corrupt the active index to something impossible.
        prefs.put(IdentityStore.KEY_ACTIVE, "99");

        var store = new IdentityStore(prefs);
        assertTrue(store.activeIndex() < store.size());
    }

    @Test
    void remove_beforeActive_decrementsActiveIndex() {
        // Need 4 identities so active can stay in bounds after removing a prior one.
        var store = new IdentityStore(prefs);
        store.add(Identity.empty("A"));
        store.add(Identity.empty("B"));
        store.add(Identity.empty("C"));
        store.setActive(2); // active is "B" (Default, A, B, C)
        assertEquals("B", store.active().name());
        store.remove(1); // remove "A" — active shifts from 2 to 1
        assertEquals(1, store.activeIndex());
        assertEquals("B", store.active().name());
    }

    @Test
    void rename_nullName_rejected() {
        var store = new IdentityStore(prefs);
        assertThrows(IllegalArgumentException.class, () -> store.rename(0, null));
    }

    @Test
    void nonNumericCountKey_fallsBackToDefaultSeed() {
        prefs.put(IdentityStore.KEY_COUNT, "not-a-number");
        var store = new IdentityStore(prefs);
        assertEquals(1, store.size());
        assertEquals("Default", store.active().name());
    }

    @Test
    void persist_wipesStaleKeysBeforeWriting() {
        // Simulate a previous session where there were 5 identities; now we only save 2.
        prefs.put(IdentityStore.PREFIX + "0", "old0");
        prefs.put(IdentityStore.PREFIX + "1", "old1");
        prefs.put(IdentityStore.PREFIX + "2", "old2");
        prefs.put(IdentityStore.PREFIX + "3", "old3");
        prefs.put(IdentityStore.PREFIX + "4", "old4");
        prefs.put(IdentityStore.KEY_COUNT, "5");
        prefs.put(IdentityStore.KEY_ACTIVE, "3");
        prefs.put("unrelated-key", "should-survive");

        var store = new IdentityStore(prefs);
        // Load fails (corrupted) -> reseeds to 1 Default identity and persists.
        assertEquals(1, store.size());

        // Stale numbered keys must be gone after the reseed.
        assertNull(prefs.get(IdentityStore.PREFIX + "3"));
        assertNull(prefs.get(IdentityStore.PREFIX + "4"));
        assertEquals("1", prefs.get(IdentityStore.KEY_COUNT));
        // Unrelated keys must be untouched.
        assertEquals("should-survive", prefs.get("unrelated-key"));
    }
}
