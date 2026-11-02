// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
class I2pLifecycleTest {
    @TempDir Path directory;
    AtomicLong clock=new AtomicLong();AtomicInteger socket=new AtomicInteger();AtomicBoolean capacity=new AtomicBoolean(true);
    I2pLifecycle owner() throws Exception { return new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),1,clock::get,p->socket.get(),capacity::get,false); }
    String config() throws Exception{return Files.readString(directory.resolve("tunnels.conf"));}
    void ack() throws Exception {
        String generation=config().split("generation=",2)[1].split("\n",2)[0];
        Files.writeString(directory.resolve("resources"),System.currentTimeMillis()/1000+" 1000 400000000 20 128 123\n");
        Files.writeString(directory.resolve("tunnels.conf.applied"),generation+" 123\n");
    }
    @Test void silentLiveLeasePreventsUnloadAndIdentityConfigurationIsStable() throws Exception {
        try(var owner=owner()){
            ack();var lease=owner.acquire(14447,"a".repeat(64));owner.tick();String active=config();assertFalse(active.contains("closeIdle"));
            socket.set(1);owner.tick();assertFalse(lease.ready().isDone());ack();owner.tick();lease.ready().join();lease.connected();
            clock.addAndGet(TimeUnit.HOURS.toNanos(3));owner.tick();assertEquals(active,config());
            lease.close();lease.close();clock.addAndGet(TimeUnit.SECONDS.toNanos(2));owner.tick();assertFalse(config().contains("port=14447"));
            ack();socket.set(0);owner.tick();var second=owner.acquire(14447,"a".repeat(64));owner.tick();assertTrue(config().contains("keys=device-"+"a".repeat(64)+".dat"));second.close();
        }
    }
    @Test void cancelledStartupAndReacquireWaitForExactRemovalAckAndPositiveAbsence() throws Exception {
        try(var owner=owner()){
            ack();var first=owner.acquire(14447,"b".repeat(64));owner.tick();String oldAck=Files.readString(directory.resolve("tunnels.conf.applied"));
            first.close();clock.addAndGet(TimeUnit.SECONDS.toNanos(2));owner.tick();assertTrue(config().contains("port=14447")); // Native may still be reading startup.
            ack();owner.tick();assertFalse(config().contains("port=14447"));var next=owner.acquire(14447,"b".repeat(64));
            Files.writeString(directory.resolve("tunnels.conf.applied"),oldAck);owner.tick();assertFalse(next.ready().isDone());
            ack();socket.set(-1);owner.tick();assertFalse(config().contains("port=14447")); // Unknown is not gone.
            socket.set(0);owner.tick();assertTrue(config().contains("port=14447"));assertFalse(next.ready().isDone());
            ack();socket.set(1);owner.tick();next.ready().get(1,TimeUnit.SECONDS);next.close();
        }
    }
    @Test void cancelledStartupCanBeReacquiredAndRemoteConnectDoesNotBlockNextDevice() throws Exception {
        try(var owner=new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),1,clock::get,p->p==14447?socket.get():0,capacity::get,false)) {
            ack();var cancelled=owner.acquire(14447,"a".repeat(64));owner.tick();cancelled.close();
            var next=owner.acquire(14447,"a".repeat(64));assertFalse(next.ready().isDone());ack();socket.set(1);owner.tick();next.ready().join();
            var other=owner.acquire(14448,"b".repeat(64));owner.tick();assertTrue(config().contains("port=14448")); // No remote CONNECT or 30-second wait on first route.
            next.close();other.close();
        }
    }
    @Test void cancellationBeforeListenerObservationCanBeReacquiredDuringWarmup() throws Exception {
        try(var owner=new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),60,clock::get,p->socket.get(),capacity::get,false)) {
            ack();var cancelled=owner.acquire(14447,"a".repeat(64));owner.tick();cancelled.close();
            ack();socket.set(1);owner.tick();assertTrue(cancelled.ready().isCompletedExceptionally());
            var warm=owner.acquire(14447,"a".repeat(64));warm.ready().get(1,TimeUnit.SECONDS);warm.close();
            clock.addAndGet(TimeUnit.SECONDS.toNanos(31));owner.tick();
            var running=owner.acquire(14447,"a".repeat(64));running.ready().get(1,TimeUnit.SECONDS);running.close();
        }
    }
    @Test void cancelledFutureCanBeReacquiredDirectlyAfterWarmupExpires() throws Exception {
        try(var owner=new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),60,clock::get,p->socket.get(),capacity::get,false)) {
            ack();var cancelled=owner.acquire(14447,"a".repeat(64));owner.tick();cancelled.close();
            ack();socket.set(1);owner.tick();clock.addAndGet(TimeUnit.SECONDS.toNanos(31));owner.tick();
            assertTrue(cancelled.ready().isCompletedExceptionally()); // RUNNING, but no earlier reacquire repaired its future.
            var running=owner.acquire(14447,"a".repeat(64));running.ready().get(1,TimeUnit.SECONDS);running.close();
        }
    }
    @Test void removedListenerObservationCannotMakeWaitingReacquisitionReady() throws Exception {
        var sockets=new java.util.HashMap<Integer,Integer>();
        try(var owner=new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),1,clock::get,p->sockets.getOrDefault(p,0),capacity::get,false)) {
            ack();var first=owner.acquire(14447,"a".repeat(64));owner.tick();ack();sockets.put(14447,1);owner.tick();first.ready().join();first.connected();
            var other=owner.acquire(14448,"b".repeat(64));owner.tick();ack();first.close();clock.addAndGet(TimeUnit.SECONDS.toNanos(2));owner.tick();
            var waiting=owner.acquire(14447,"a".repeat(64));ack();sockets.put(14447,0);owner.tick();
            assertFalse(config().contains("port=14447")); // Other unobserved startup holds this route in WAITING.
            waiting.close();var retried=owner.acquire(14447,"a".repeat(64));assertFalse(retried.ready().isDone());
            sockets.put(14448,1);owner.tick();owner.tick();assertTrue(config().contains("port=14447"));assertFalse(retried.ready().isDone());
            ack();owner.tick();assertFalse(retried.ready().isDone());
            sockets.put(14447,1);owner.tick();retried.ready().get(1,TimeUnit.SECONDS);retried.close();other.close();
        }
    }
    @Test void pressureRejectsNewActivationWithoutTouchingExistingLease() throws Exception {
        try(var owner=owner()){
            ack();var active=owner.acquire(14447,"a".repeat(64));owner.tick();ack();socket.set(1);owner.tick();active.ready().join();active.connected();String before=config();
            capacity.set(false);var refused=owner.acquire(14448,"b".repeat(64));owner.tick();assertTrue(refused.ready().isCompletedExceptionally());assertEquals(before,config());refused.close();active.close();
        }
    }
    @Test void listenerProbeResolvesConfiguredHostInsteadOfUsingNullOrStartupAddress() throws Exception {
        int port;
        try(var listener=new ServerSocket(0,10,InetAddress.getByName("127.0.0.2"));
            var owner=new I2pLifecycle(directory,InetSocketAddress.createUnresolved("127.0.0.2",4447),1,clock::get,null,()->true,false)) {
            port=listener.getLocalPort();ack();var lease=owner.acquire(port,"a".repeat(64));owner.tick();
            assertFalse(config().contains("port="+port));assertFalse(lease.ready().isDone());
            listener.close();
            try(var probe=new Socket()) {
                var refusal=assertThrows(ConnectException.class,()->probe.connect(new InetSocketAddress("127.0.0.2",port),100));
                assertEquals(0,I2pLifecycle.listenerFailure(refusal));
            }
            owner.tick();assertTrue(config().contains("port="+port));ack();
            try(var replacement=new ServerSocket(port,10,InetAddress.getByName("127.0.0.2"))) {
                owner.tick();assertTrue(lease.ready().isDone());assertFalse(lease.ready().isCompletedExceptionally());
            }
            lease.close();
        }
    }
    @Test void uncertainConnectionFailuresNeverProveListenerAbsence() {
        assertEquals(-1,I2pLifecycle.listenerFailure(new ConnectException()));
        assertEquals(-1,I2pLifecycle.listenerFailure(new ConnectException("Network is unreachable")));
        assertEquals(-1,I2pLifecycle.listenerFailure(new ConnectException("Connection refused: unexpected detail")));
        assertEquals(-1,I2pLifecycle.listenerFailure(new SocketTimeoutException("Connect timed out")));
        assertEquals(-1,I2pLifecycle.listenerFailure(new java.io.IOException("Connection refused (connect failed)")));
    }
    @Test void nextActivationWaitsForListenerAndFreshSampleButNotRemoteConnection() throws Exception {
        try(var owner=new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),1,clock::get,p->p==14447?socket.get():0,null,false)) {
            ack();var first=owner.acquire(14447,"a".repeat(64));owner.tick();
            var second=owner.acquire(14448,"b".repeat(64));owner.tick();assertFalse(config().contains("port=14448"));
            ack();owner.tick();assertFalse(config().contains("port=14448")); // Ack without listener is insufficient.
            socket.set(1);owner.tick();first.ready().join();
            owner.tick();assertFalse(config().contains("port=14448"));
            long sampled=Long.parseLong(Files.readString(directory.resolve("resources")).split(" ")[0]);
            while(System.currentTimeMillis()/1000<=sampled)Thread.sleep(10);
            ack();owner.tick();assertTrue(config().contains("port=14448"));first.close();second.close();
        }
    }
    @Test void overlappingWarmupsReserveHeadroomWithoutEvictingLiveConnections() throws Exception {
        try(var owner=new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),1,clock::get,p->p==14447?socket.get():0,null,false)) {
            ack();var first=owner.acquire(14447,"a".repeat(64));owner.tick();ack();socket.set(1);owner.tick();first.ready().join();
            long sampled=Long.parseLong(Files.readString(directory.resolve("resources")).split(" ")[0]);
            while(System.currentTimeMillis()/1000<=sampled)Thread.sleep(10);
            ack();Files.writeString(directory.resolve("resources"),System.currentTimeMillis()/1000+" 1000 50000000 20 128 123\n");
            var second=owner.acquire(14448,"b".repeat(64));owner.tick();
            assertTrue(second.ready().isCompletedExceptionally()); // Enough for one allowance, not two.
            assertTrue(config().contains("port=14447"));assertFalse(config().contains("port=14448"));second.close();owner.tick();
            clock.addAndGet(TimeUnit.SECONDS.toNanos(31));owner.tick(); // First allocation now represented by telemetry.
            var third=owner.acquire(14449,"c".repeat(64));owner.tick();assertTrue(config().contains("port=14449"));
            first.close();third.close();
        }
    }
    @Test void staleTelemetryFreezesMutationAndRestartRemovesLeftoversBeforeReuse() throws Exception {
        try(var owner=owner()){
            ack();var lease=owner.acquire(14447,"a".repeat(64));owner.tick();ack();socket.set(1);owner.tick();lease.connected();lease.close();
            Files.writeString(directory.resolve("resources"),"0 1000 400000000 20 128 123\n");String before=config();clock.addAndGet(TimeUnit.SECONDS.toNanos(2));owner.tick();assertEquals(before,config());
            assertThrows(Exception.class,()->owner());
        }
        Files.writeString(directory.resolve("tunnels.conf"),"[device-old]\nport=14447\n"); // Simulate a crashed owner snapshot.
        try(var next=owner()){
            assertFalse(config().contains("port=14447"));var lease=next.acquire(14447,"a".repeat(64));ack();socket.set(1);next.tick();assertFalse(lease.ready().isDone());socket.set(0);next.tick();assertTrue(config().contains("port=14447"));lease.close();
        }
    }
    @Test void restoredSnapshotDoesNotPublishUnrecordedPortUntilItsListenerIsAbsent() throws Exception {
        Files.writeString(directory.resolve("tunnels.conf"),"[device-old]\nport=14447\n");
        var sockets=new java.util.HashMap<Integer,Integer>();
        sockets.put(14447,1);sockets.put(14448,1);
        try(var owner=new I2pLifecycle(directory,new InetSocketAddress("127.0.0.1",4447),1,clock::get,p->sockets.getOrDefault(p,-1),capacity::get,false)) {
            ack();var lease=owner.acquire(14448,"b".repeat(64));String empty=config();
            owner.tick();assertEquals(empty,config());assertFalse(lease.ready().isDone());
            sockets.put(14448,-1);owner.tick();assertEquals(empty,config());assertFalse(lease.ready().isDone());
            sockets.put(14448,0);owner.tick();assertTrue(config().contains("port=14448"));
            assertFalse(config().contains("port=14447"));assertFalse(lease.ready().isDone());
            ack();sockets.put(14448,1);owner.tick();lease.ready().get(1,TimeUnit.SECONDS);lease.connected();
            String active=config();sockets.put(14448,-1);owner.tick();assertEquals(active,config());
            lease.close();
        }
    }
    String observation(I2pLifecycle owner) throws Exception { owner.writeObservation();return Files.readString(directory.resolve("status.json")); }
    @Test void observationsDistinguishPendingConnectedCancelledCooldownAndRemoval() throws Exception {
        try(var owner=owner()) {
            ack();assertTrue(observation(owner).contains("\"devices\":{}"));
            var first=owner.acquire(14447,"a".repeat(64));assertTrue(observation(owner).contains("\"14447\":\"WAITING\""));
            owner.tick();assertTrue(observation(owner).contains("\"available\":false"));ack();socket.set(1);owner.tick();first.ready().join();
            assertTrue(observation(owner).contains("\"14447\":\"STARTING\""));
            clock.addAndGet(TimeUnit.SECONDS.toNanos(31));owner.tick(); // Maintenance RUNNING does not mean CONNECT succeeded.
            assertTrue(observation(owner).contains("\"14447\":\"STARTING\""));
            first.connected();first.connected();assertTrue(observation(owner).contains("CONNECTIONS_OPEN"));
            var pending=owner.acquire(14447,"a".repeat(64));first.close();first.close();
            assertTrue(observation(owner).contains("\"14447\":\"STARTING\""));
            pending.close();pending.connected();assertTrue(observation(owner).contains("COOLDOWN"));
            clock.addAndGet(TimeUnit.SECONDS.toNanos(2));owner.tick();ack();assertTrue(observation(owner).contains("STOPPING"));
            socket.set(0);owner.tick();assertTrue(observation(owner).contains("\"devices\":{}"));
            assertFalse(observation(owner).contains("a".repeat(64)));
            assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(directory.resolve("status.json")));
        }
    }
    @Test void statusFailureCannotBreakForwardingAndStaleNativeTelemetryIsUnavailable() throws Exception {
        try(var owner=owner()) {
            ack();var lease=owner.acquire(14447,"a".repeat(64));owner.tick();ack();socket.set(1);owner.tick();lease.connected();
            Files.writeString(directory.resolve("resources"),"0 1000 400000000 20 128 123\n");
            assertTrue(observation(owner).contains("\"available\":false"));
            Files.delete(directory.resolve("status.json"));Files.createDirectory(directory.resolve("status.json"));
            assertDoesNotThrow(owner::writeObservation);ack();owner.tick();assertTrue(config().contains("port=14447"));lease.close();
        }
    }
}
