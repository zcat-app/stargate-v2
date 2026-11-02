// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class DockerCaptureTest {
    private static final String TOKEN="0".repeat(32),IMAGE="sha256:"+"a".repeat(64),WRITER="d".repeat(64);
    static final class Work implements DockerCapture.Work {
        boolean prepared,published,retained; public void guard(boolean empty){} public void prepare(){prepared=true;} public void publish(){published=true;}
        public void retain(){retained=true;} public String location(){return "/synthetic/work";} public ArchiveInspector.Summary summary(){return new ArchiveInspector.Summary(5,0,false);}
    }
    private static DockerImportTest.Fake fake() throws Exception {
        var d=new DockerImportTest.Fake(); var factory=JsonNodeFactory.instance;
        for(String role:DockerPolicy.BASE){ObjectNode v=factory.objectNode();v.put("Name",role).put("Driver","local").put("Scope","local").putNull("Options").put("CreatedAt","created-"+role).put("Mountpoint","/var/lib/docker/"+role);v.putObject("Labels");d.volumes.put(role,v);d.attachments.put(role,Set.of(WRITER));}
        ObjectNode writer=factory.objectNode();writer.put("Id",WRITER).put("Name","/writer").put("Image","image");writer.putArray("Mounts");
        writer.putObject("State").put("Running",false).put("Status","exited").put("Paused",false).put("Restarting",false).put("Dead",false);d.containers.put(WRITER,writer);return d;
    }
    private static DockerCapture.Plan plan(){Map<String,String> volumes=new HashMap<>();for(String role:DockerPolicy.BASE)volumes.put(role,role);
        return new DockerCapture.Plan(TOKEN,IMAGE,new DockerPolicy.Selection(volumes,Set.of(WRITER)),false,"/synthetic/out/archive.age","/synthetic/out","/synthetic/journal","/synthetic/key","/synthetic/work/core.jar","/synthetic/work/adapter.jar","/synthetic/work/archive.tar",Map.of("core.jar","1".repeat(64),"adapter.jar","2".repeat(64)));}
    @Test void capturesOnlyStoppedMatchingSourcesAndCleansKnownHelper() throws Exception {
        var docker=fake();var journal=new DockerImportTest.Journal();var work=new Work();DockerCapture.run(plan(),docker,journal,work);
        assertTrue(work.prepared);assertTrue(work.published);assertFalse(work.retained);assertEquals("capture_success",journal.events.getLast());
        assertEquals(1,docker.calls.stream().filter(s->s.startsWith("rm ")).count());assertTrue(docker.containers.containsKey(WRITER));
    }
    @Test void uncertainOrUnvalidatedHelpersRetainWorkAndAreNeverGuessed() throws Exception {
        var uncertain=fake();uncertain.failContainerCreate=true;var journal=new DockerImportTest.Journal();var work=new Work();
        assertThrows(Exception.class,()->DockerCapture.run(plan(),uncertain,journal,work));assertTrue(work.retained);assertFalse(work.published);assertFalse(uncertain.calls.stream().anyMatch(s->s.startsWith("rm ")));
        var bad=fake();bad.badCaptureCaps=true;var second=new Work();assertThrows(Exception.class,()->DockerCapture.run(plan(),bad,new DockerImportTest.Journal(),second));
        assertTrue(second.retained);assertEquals(0,bad.calls.stream().filter(s->s.startsWith("start --attach")).count());assertFalse(bad.calls.stream().anyMatch(s->s.startsWith("rm ")));
        var base=fake();var alias=new DockerImportTest.Fake(){@Override public String call(long timeout,String...args)throws Exception{if(args[0].equals("create"))return WRITER;return super.call(timeout,args);}};
        alias.volumes.putAll(base.volumes);alias.containers.putAll(base.containers);alias.attachments.putAll(base.attachments);var third=new Work();
        assertThrows(Exception.class,()->DockerCapture.run(plan(),alias,new DockerImportTest.Journal(),third));assertTrue(third.retained);
        assertTrue(alias.containers.containsKey(WRITER));assertFalse(alias.calls.stream().anyMatch(s->s.startsWith("rm ")));
    }
    @Test void changedSourcePreventsPublicationAndOnlyKnownHelperIsRemoved() throws Exception {
        var changed=fake();changed.changedVolume=true;var work=new Work();assertThrows(Exception.class,()->DockerCapture.run(plan(),changed,new DockerImportTest.Journal(),work));
        assertFalse(work.published);assertFalse(work.retained);assertEquals(1,changed.calls.stream().filter(s->s.startsWith("rm ")).count());assertTrue(changed.containers.containsKey(WRITER));
    }
    @Test void cancellationDuringKnownHelperCleanupIsDeferredUntilRemoval() throws Exception {
        var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var base=fake();
        var docker=new DockerImportTest.Fake(){
            @Override public String call(long timeout,String...args)throws Exception{
                if(args[0].equals("rm")){entered.countDown();assertTrue(release.await(10,java.util.concurrent.TimeUnit.SECONDS));}
                return super.call(timeout,args);
            }
        };
        docker.volumes.putAll(base.volumes);docker.containers.putAll(base.containers);docker.attachments.putAll(base.attachments);
        var cancellation=new java.util.concurrent.atomic.AtomicReference<Cancellation>();var interrupted=new java.util.concurrent.atomic.AtomicBoolean();var work=new Work();
        Thread worker=new Thread(()->{Cancellation signal=new Cancellation(Thread.currentThread());cancellation.set(signal);
            try{DockerCapture.run(plan(),docker,new DockerImportTest.Journal(),work,signal);fail("Cancellation must fail the operation");}
            catch(Exception expected){interrupted.set(Thread.currentThread().isInterrupted());}});
        worker.start();try{
            assertTrue(entered.await(10,java.util.concurrent.TimeUnit.SECONDS));cancellation.get().request();release.countDown();worker.join(10_000);
            assertFalse(worker.isAlive());assertTrue(interrupted.get());assertFalse(work.published);assertFalse(work.retained);
            assertEquals(1,docker.calls.stream().filter(s->s.startsWith("rm ")).count());assertTrue(docker.containers.containsKey(WRITER));
        }finally{release.countDown();if(worker.isAlive())worker.interrupt();}
    }
}
