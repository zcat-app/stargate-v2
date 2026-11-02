package app.zcat.stargate.monitor;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class MonitorLedgerTest {
    @TempDir Path temp;
    static final Instant NOW=Instant.parse("2026-10-31T09:00:00Z");
    Path privateDir() throws Exception {Files.setPosixFilePermissions(temp,PosixFilePermissions.fromString("rwx------"));return temp;}
    MonitorLedger ledger() throws Exception {Path path=privateDir().resolve("state.json");MonitorFiles.create(path,MonitorFiles.bytes(MonitorLedger.initial(129600,NOW)));return new MonitorLedger(path);}
    @Test void movingJavaBaselineToSharedJsonDoesNotChangeReleaseFingerprint() throws Exception {
        var before=MonitorFiles.object();before.putObject("upstream").put("release_name","jdk-25.0.5+8").put("openjdk_version","25.0.5+8-LTS");
        before.putObject("source_baseline").put("source","tools/prepare_container.py").put("version","25.0.5");
        var after=before.deepCopy();((ObjectNode)after.get("source_baseline")).put("source","containers/java-runtime.json");
        assertEquals(MonitorFiles.fingerprint(MonitorLedger.releaseSelected("temurin",before)),MonitorFiles.fingerprint(MonitorLedger.releaseSelected("temurin",after)));
    }
    static ObjectNode report(Instant now) {
        var r=MonitorFiles.object().put("completed_at",now.toString()).put("outcome","observed");var checks=r.putObject("checks");for(String n:MonitorLedger.NAMES.subList(0,7)) {
            var o=checks.putObject(n).put("outcome","observed").putObject("observation");o.put("checked_at",now.toString()).put("observed_at_utc",now.toString()).put("latest_tag","v1.0.0").put("latest_published_at","2026-10-30T00:00:00Z").put("family","3.40").put("greatest_numeric_version","3.40.1.1").put("metadata_last_updated","2026-10-30T00:00:00Z").put("selected_tag","v1.0.0").put("sha256","a".repeat(64));o.putObject("upstream").put("release_name","jdk-25.0.5+8").put("openjdk_version","25.0.5+8");o.putArray("modules");o.putObject("packages").putObject("tor").putObject("published").put("version","0.4.9.14");
        }
        for(String n:List.of("advisories","quarkus_advisories")){var a=checks.putObject(n).put("outcome","observed").putObject("observation").put("status","observed").put("security_status","not_assessed").put("checked_at",now.toString());a.putArray("candidates");}return r;
    }
    static ObjectNode runtime(Instant now) {
        var r=MonitorFiles.object().put("security_status","not_assessed");r.putObject("deployment_binding").put("status","observed").put("checked_at",now.toString());var image=r.putObject("images").putObject("app").put("image_id","sha256:"+"a".repeat(64));image.putObject("scan").putObject("source_binding").put("selected_image_id","sha256:"+"a".repeat(64)).put("trivy_json_sha256","b".repeat(64));var osv=r.putObject("osv_observation").put("status","observed").put("checked_at",now.toString());var q=osv.putArray("queries").addObject().put("ecosystem","Maven").put("name","io.netty:netty-common").put("version","4.1.135.Final");q.putArray("selected_records").addObject().put("role","app").put("image_id","sha256:"+"a".repeat(64)).put("evidence","extracted_jar");q.putArray("candidates");return r;
    }
    @Test void baselineQuietChangesOnceAndUnknownIsSticky() throws Exception {
        var l=ledger();l.collect(report(NOW),runtime(NOW),NOW,129600);assertTrue(l.state.path("pending").isNull());
        var second=NOW.plusSeconds(60);l.collect(report(second),runtime(second),second,129600);assertTrue(l.state.path("pending").isNull());
        var third=second.plusSeconds(60);l.collect(report(third),MonitorFiles.object(),third,129600);assertTrue(l.state.path("pending").path("text").asText().contains("Could not check: server software report."));long sequence=l.state.path("sequence").asLong();
        assertThrows(IllegalStateException.class,()->l.collect(report(third),runtime(third),third,129600));assertEquals(sequence,l.state.path("sequence").asLong());
        l.acknowledge();l.collect(report(third.plusSeconds(60)),MonitorFiles.object(),third.plusSeconds(60),129600);assertTrue(l.state.path("pending").isNull());
        l.collect(report(third.plusSeconds(120)),runtime(third.plusSeconds(120)),third.plusSeconds(120),129600);assertTrue(l.state.path("pending").path("text").asText().contains("Checking works again: server software report."));
    }
    @Test void staleConflictingAndBackwardsEvidenceFailsClosed() throws Exception {
        var l=ledger();l.collect(report(NOW),runtime(NOW),NOW,129600);var changed=report(NOW);((ObjectNode)changed.path("checks").path("nym").path("observation")).put("latest_tag","other");
        l.collect(changed,runtime(NOW),NOW,129600);assertEquals("unknown",l.state.path("checks").path("nym").path("health").asText());l.acknowledge();assertThrows(IllegalArgumentException.class,()->l.collect(report(NOW),runtime(NOW),NOW.minusSeconds(1),129600));assertThrows(IllegalArgumentException.class,()->l.collect(report(NOW),runtime(NOW),NOW,900));
    }
    @Test void acceptedReceiptRecoversWithoutSendingAndUnknownNeverRetries() throws Exception {
        Path dir=privateDir();String id="a".repeat(32)+"-1";AtomicInteger sends=new AtomicInteger();MonitorSender.Send send=b->{sends.incrementAndGet();return "ACCEPTED";};
        assertEquals("ACCEPTED",MonitorSender.dispatch(dir,id,"bounded alert\n",send));assertEquals("RECOVERED_ACCEPTED",MonitorSender.dispatch(dir,id,"bounded alert\n",send));assertEquals(1,sends.get());
        String uncertain="a".repeat(32)+"-2";MonitorFiles.create(dir.resolve("event-"+uncertain+".attempt"),"UNKNOWN\n".getBytes());assertEquals("BLOCKED",MonitorSender.dispatch(dir,uncertain,"bounded alert\n",send));assertEquals(1,sends.get());
    }
    @Test void publicSnapshotsKeepInodeAndExactManagerContract() throws Exception {
        Path dir=privateDir();Path file=dir.resolve("snapshot.json");var v=MonitorFiles.object().put("schema_version",1).put("latest","observed").put("attempt_at",NOW.toString()).put("published_at",NOW.toString());MonitorFiles.publish(file,v);Object inode=Files.getAttribute(file,"unix:ino");v.put("published_at",NOW.plusSeconds(30).toString());MonitorFiles.publish(file,v);assertEquals(inode,Files.getAttribute(file,"unix:ino"));assertEquals(0644,((Number)Files.getAttribute(file,"unix:mode")).intValue()&0777);assertEquals(4,MonitorFiles.json(file,512,false).size());
    }
    @Test void symlinkAndWritableStateAreRefused() throws Exception {
        Path dir=privateDir();Path target=dir.resolve("target");MonitorFiles.create(target,"{}".getBytes());Path link=dir.resolve("link");Files.createSymbolicLink(link,target);assertThrows(Exception.class,()->MonitorFiles.read(link,32,true));Files.setPosixFilePermissions(target,PosixFilePermissions.fromString("rw-rw----"));assertThrows(Exception.class,()->MonitorFiles.read(target,32,true));
    }
    @Test void repeatedFailedCollectionRemainsUnknownEvenWithoutNewAlert() throws Exception {
        Path base=privateDir();Path ledger=Files.createDirectory(base.resolve("ledger")),out=Files.createDirectory(base.resolve("output")),dispatch=Files.createDirectory(base.resolve("dispatch"));for(Path d:List.of(ledger,dispatch))Files.setPosixFilePermissions(d,PosixFilePermissions.fromString("rwx------"));
        Files.setPosixFilePermissions(out,PosixFilePermissions.fromString("rwxr-xr-x"));var current=MonitorMain.now();MonitorFiles.create(ledger.resolve("state.json"),MonitorFiles.bytes(MonitorLedger.initial(129600,current.minusSeconds(1))));
        var c=new MonitorMain.Config(base,base,out,ledger,dispatch,base,"3",base,"3.40","25.0.5+8","v1.3.2",base,base,base,900,129600);
        AtomicInteger sends=new AtomicInteger();MonitorMain.Collection broken=config->List.of(report(current),MonitorFiles.object());MonitorSender.Send send=body->{sends.incrementAndGet();return "ACCEPTED";};
        assertEquals(2,MonitorMain.run(c,broken,send));assertEquals(1,sends.get());assertEquals("unknown",MonitorFiles.json(out.resolve("snapshot.json"),512,false).path("latest").asText());
        assertEquals(2,MonitorMain.run(c,broken,send));assertEquals(1,sends.get());var value=MonitorFiles.json(out.resolve("consumer-snapshot.json"),512,false);assertEquals("collection_unknown",value.path("outcome").asText());assertEquals("not_attempted",value.path("local_acceptance").asText());assertFalse(value.path("future_collection_blocked").asBoolean());
    }
    @Test void timestampedFailureCannotBeOverriddenByOlderOrEqualSuccess() throws Exception {
        var l=ledger();l.collect(report(NOW),runtime(NOW),NOW,129600);Instant failed=NOW.plusSeconds(60);var r=report(failed);((ObjectNode)r.path("checks").path("nym")).put("outcome","unknown");l.collect(r,runtime(failed),failed,129600);l.acknowledge();assertEquals(failed.toString(),l.state.path("checks").path("nym").path("watermark").asText());
        l.collect(report(NOW.plusSeconds(30)),runtime(failed),failed,129600);assertEquals("unknown",l.state.path("checks").path("nym").path("health").asText());if(!l.state.path("pending").isNull())l.acknowledge();l.collect(report(failed),runtime(failed),failed,129600);assertEquals("unknown",l.state.path("checks").path("nym").path("health").asText());
    }
    @Test void wordingUpgradeDoesNotRewriteOrRecollectAnExistingPendingEvent() throws Exception {
        Path base=privateDir(),directory=Files.createDirectory(base.resolve("ledger")),out=Files.createDirectory(base.resolve("output")),dispatch=Files.createDirectory(base.resolve("dispatch"));
        for(Path d:List.of(directory,dispatch))Files.setPosixFilePermissions(d,PosixFilePermissions.fromString("rwx------"));Files.setPosixFilePermissions(out,PosixFilePermissions.fromString("rwxr-xr-x"));
        var state=MonitorLedger.initial(129600,MonitorMain.now());state.put("sequence",1);var pending=state.putObject("pending");pending.put("event_id",state.path("epoch").asText()+"-1");
        String original="Unknown/failed: Runtime security evidence.\nCoverage incomplete/unverified; impact/deployment unknown.\n";pending.put("text",original);
        MonitorFiles.create(directory.resolve("state.json"),MonitorFiles.bytes(state));var c=new MonitorMain.Config(base,base,out,directory,dispatch,base,"3",base,"3.40","25.0.5+8","v1.3.2",base,base,base,900,129600);
        AtomicInteger sends=new AtomicInteger();assertEquals(4,MonitorMain.run(c,config->{fail("must not collect over pending work");return null;},body->{assertEquals(original,new String(body,java.nio.charset.StandardCharsets.UTF_8));sends.incrementAndGet();return "ACCEPTED";}));
        assertEquals(1,sends.get());var result=new MonitorLedger(directory.resolve("state.json"));assertTrue(result.state.path("pending").isNull());assertEquals(1,result.state.path("sequence").asLong());
        assertEquals("fresh_observation_required",MonitorFiles.json(out.resolve("consumer-snapshot.json"),512,false).path("outcome").asText());
    }
}
