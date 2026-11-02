// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class InitRootsTest {
    static final class Fake implements InitRoots.Roots {
        final Set<String> names; final List<String> writes = new ArrayList<>(); String bad; boolean synced;
        Fake(boolean nym) { names = new HashSet<>(DockerPolicy.roots(nym)); }
        public Set<String> names() { return names; }
        public void checkEmptyRoot(String name) throws Exception { if (name.equals(bad)) throw new Exception("not empty"); }
        public void initialize(String name) { writes.add(name); }
        public void syncParent() { synced = true; }
        public void close() { }
    }
    @Test void preflightsAllRootsBeforeAnyInitialization() throws Exception {
        for (boolean nym : List.of(false,true)) {
            Fake fake = new Fake(nym); InitRoots.initialize(DockerPolicy.roots(nym), fake);
            assertEquals(DockerPolicy.roots(nym), fake.writes); assertTrue(fake.synced);
            Fake unsafe = new Fake(nym); unsafe.bad = "tor-data";
            assertThrows(Exception.class, () -> InitRoots.initialize(DockerPolicy.roots(nym), unsafe)); assertTrue(unsafe.writes.isEmpty());
            Fake archive = new Fake(nym); archive.names.add("scratch"); var withScratch = new ArrayList<>(DockerPolicy.roots(nym)); withScratch.add("scratch");
            InitRoots.initialize(withScratch, archive); assertEquals(withScratch, archive.writes);
        }
    }
}
