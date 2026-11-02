// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class DockerArchiveImportTest {
    private static final String TOKEN="0".repeat(32), IMAGE="sha256:"+"a".repeat(64), DIGEST="d".repeat(64);
    private static DockerArchiveImport.Plan plan(boolean nym){String dir="/synthetic/stargate-archive-"+TOKEN;return new DockerArchiveImport.Plan(TOKEN,IMAGE,dir,dir+"/authenticated.tar",DIGEST,dir+"/core.jar",dir+"/adapter.jar",Map.of("core.jar","1".repeat(64),"adapter.jar","2".repeat(64)),nym);}
    @Test void rejectsUnauthenticatedSpoolBeforeAnyDaemonCall() throws Exception {
        var docker=new DockerImportTest.Fake(); var journal=new DockerImportTest.Journal();
        assertThrows(Exception.class,()->DockerArchiveImport.run(plan(false),docker,journal,()->{},()->{throw new java.io.IOException("Synthetic bad digest");}));
        assertTrue(docker.calls.isEmpty()); assertTrue(journal.events.isEmpty());
    }
    @Test void usesScratchAndIsolatedHelpersForFiveAndSevenRoots() throws Exception {
        for(boolean nym:List.of(false,true)) {
            var docker=new DockerImportTest.Fake();var journal=new DockerImportTest.Journal();
            DockerArchiveImport.run(plan(nym),docker,journal,()->{},()->{});
            assertEquals(nym?8:6,docker.volumes.size());assertEquals(2,docker.containers.size());assertEquals("success",journal.events.getLast());
            assertFalse(docker.calls.stream().anyMatch(s->s.startsWith("rm ")||s.startsWith("volume rm")));
        }
    }
    @Test void changedSpoolOrBadCapabilitiesPreventsPayloadStart() throws Exception {
        var docker=new DockerImportTest.Fake();var journal=new DockerImportTest.Journal();AtomicInteger guards=new AtomicInteger();
        assertThrows(Exception.class,()->DockerArchiveImport.run(plan(false),docker,journal,()->{},()->{if(guards.incrementAndGet()==4) throw new java.io.IOException("Synthetic changed spool");}));
        assertTrue(docker.calls.stream().filter(s->s.startsWith("start --attach")).count()<=1);
        var bad=new DockerImportTest.Fake();bad.badCopyCaps=true;var journal2=new DockerImportTest.Journal();
        assertThrows(Exception.class,()->DockerArchiveImport.run(plan(false),bad,journal2,()->{},()->{}));
        assertEquals(1,bad.calls.stream().filter(s->s.startsWith("start --attach")).count());
    }
    @Test void handoffReconcilesArchiveImportAndOmitsScratch() throws Exception {
        var docker=new DockerImportTest.Fake();var journal=new DockerImportTest.Journal();var plan=plan(false);
        journal.record("archive_planned",Map.of("schema","java-authenticated-archive-import-v1","token",TOKEN,"image",IMAGE,"private_dir",plan.directory()));
        DockerArchiveImport.run(plan,docker,journal,()->{},()->{});
        var result=ComposeHandoff.validate(journal.records,java.nio.file.Path.of("/synthetic/stargate-import-"+TOKEN+".jsonl"),docker);
        @SuppressWarnings("unchecked") Map<String,Map<String,Object>> volumes=(Map<String,Map<String,Object>>)result.get("volumes");
        assertFalse(volumes.containsKey("scratch"));assertTrue(volumes.get("nym-data").get("name").toString().startsWith("stargate-unavailable-"));
        ((com.fasterxml.jackson.databind.node.ObjectNode)docker.volumes.values().iterator().next()).put("CreatedAt","replaced");
        assertThrows(Exception.class,()->ComposeHandoff.validate(journal.records,java.nio.file.Path.of("/synthetic/stargate-import-"+TOKEN+".jsonl"),docker));
    }
    @Test void retiredAndUnknownArchiveSchemasAreRefusedBeforeAnyDaemonCall() throws Exception {
        for (boolean nym : List.of(false, true)) {
            var fixture = new DockerImportTest.Fake();
            var journal = new DockerImportTest.Journal();
            var selected = plan(nym);
            journal.record("archive_planned", Map.of("schema", "java-authenticated-archive-import-v1",
                    "token", TOKEN, "image", IMAGE, "private_dir", selected.directory()));
            DockerArchiveImport.run(selected, fixture, journal, () -> {}, () -> {});
            for (String schema : new String[]{"authenticated-archive-import-v1", "unknown-archive-import-v1", "", null}) {
                var planned = (com.fasterxml.jackson.databind.node.ObjectNode)journal.records.getFirst();
                if (schema == null) planned.remove("schema"); else planned.put("schema", schema);
                var calls = new AtomicInteger();
                DockerTransport forbidden = (timeout, arguments) -> {
                    calls.incrementAndGet(); throw new java.io.IOException("No daemon access permitted for an unsupported journal");
                };
                var path = java.nio.file.Path.of("/synthetic/stargate-import-" + TOKEN + ".jsonl");
                assertThrows(Exception.class, () -> ComposeHandoff.validate(journal.records, path, forbidden));
                assertEquals(0, calls.get(), "Unsupported archive journals must fail before daemon calls, including inspect");
            }
        }
    }
}
