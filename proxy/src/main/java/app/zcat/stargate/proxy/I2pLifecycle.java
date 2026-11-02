// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.io.IOException;
import java.net.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;

/** The proxy owns demand. Only zero-reference destinations may be removed. No activity timer. */
final class I2pLifecycle implements AutoCloseable {
    enum State { WAITING, STARTING, RUNNING, STOPPING, FAILED }
    private static final java.nio.file.attribute.FileAttribute<?> PRIVATE = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
    private final Path directory;
    private final InetSocketAddress router;
    private final long cooldownNanos;
    private final Map<Integer, Entry> entries = new TreeMap<>();
    private final ScheduledExecutorService worker;
    private final boolean asynchronous;
    private final FileChannel ownership;
    private final FileLock lock;
    private boolean closed, faulted;
    private String generation;
    private long nextAdmissionAfter;
    private final boolean injectedCapacity;
    private final java.util.function.LongSupplier clock;
    private final java.util.function.IntUnaryOperator listening;
    private final java.util.function.BooleanSupplier capacity;
    private static final class Entry {
        final int port; final String key;
        State state; int references, connected; long unusedSince, listenerReadyAt; boolean listenerObserved;
        CompletableFuture<Void> ready = new CompletableFuture<>();
        Entry(int port, String key, State state) { this.port=port;this.key=key;this.state=state; }
    }
    final class Lease implements AutoCloseable {
        private final Entry entry;
        private final CompletableFuture<Void> ready;
        private boolean connected;
        private final java.util.concurrent.atomic.AtomicBoolean released=new java.util.concurrent.atomic.AtomicBoolean();
        Lease(Entry entry) { this.entry=entry;this.ready=entry.ready; }
        CompletableFuture<Void> ready() { return ready; }
        void connected() { dispatch(()-> { synchronized(I2pLifecycle.this) { if(!released.get() && !connected){connected=true;entry.connected++;if(entry.state==State.STARTING){entry.state=State.RUNNING;nextAdmissionAfter=System.currentTimeMillis()/1000;}} } }); }
        @Override public void close() {
            if(released.compareAndSet(false,true))dispatch(()-> { synchronized(I2pLifecycle.this) {
                if(connected){connected=false;entry.connected--;}
                if(--entry.references==0){entry.unusedSince=clock.getAsLong();if(!entry.ready.isDone())entry.ready.completeExceptionally(new CancellationException());}
            } });
        }
    }
    private void dispatch(Runnable work) {
        if(!asynchronous){work.run();return;}
        try{worker.execute(work);}catch(RejectedExecutionException ignored){}
    }
    CompletableFuture<Lease> acquireAsync(int port,String key) {
        var result=new CompletableFuture<Lease>();
        try { worker.execute(()-> {try{result.complete(acquire(port,key));}catch(Exception e){result.completeExceptionally(e);} }); }
        catch(RejectedExecutionException e){result.completeExceptionally(e);}
        return result;
    }

    I2pLifecycle(Path directory, InetSocketAddress router, int cooldownSeconds) throws IOException {
        this(directory,router,cooldownSeconds,System::nanoTime,null,null,true);
    }
    I2pLifecycle(Path directory, InetSocketAddress router, int cooldownSeconds, java.util.function.LongSupplier clock,
                 java.util.function.IntUnaryOperator listening, java.util.function.BooleanSupplier capacity, boolean schedule) throws IOException {
        this.injectedCapacity=capacity!=null;this.asynchronous=schedule;this.directory=directory;this.router=router;this.cooldownNanos=TimeUnit.SECONDS.toNanos(cooldownSeconds);this.clock=clock;
        this.listening=listening==null ? this::listening : listening;this.capacity=capacity==null ? this::capacity : capacity;
        ownership=FileChannel.open(directory.resolve("lifecycle.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
        try { lock=ownership.tryLock(); if (lock==null) throw new IOException("I2P_LIFECYCLE_ALREADY_OWNED"); }
        catch (IOException|RuntimeException e) { ownership.close();throw e; }
        worker=Executors.newSingleThreadScheduledExecutor(r->Thread.ofPlatform().daemon().name("i2p-lifecycle").unstarted(r));
        try {
            // The previous proxy is gone (exclusive process lock). Remove its fleet before reuse.
            Path tunnels=directory.resolve("tunnels.conf");
            if (Files.exists(tunnels)) {
                if (Files.size(tunnels)>131072) throw new IOException("I2P_CONFIGURATION_TOO_LARGE");
                var ports=java.util.regex.Pattern.compile("(?m)^port=([0-9]+)$").matcher(Files.readString(tunnels));
                while (ports.find()) { int p=Integer.parseInt(ports.group(1)); if(p<14447||p>65535)throw new IOException("I2P_INVALID_PORT"); entries.put(p,new Entry(p,"",State.STOPPING)); }
            }
            publish();
            if(schedule){
                worker.scheduleWithFixedDelay(this::tick,0,200,TimeUnit.MILLISECONDS);
                worker.scheduleWithFixedDelay(this::writeObservation,0,1,TimeUnit.SECONDS);
            }
        } catch(IOException|RuntimeException e) { worker.shutdownNow();lock.release();ownership.close();throw e; }
    }
    synchronized Lease acquire(int port, String key) {
        if(closed || faulted || port<14447 || port>65535 || !key.matches("[a-f0-9]{64}"))throw new IllegalStateException("I2P_LIFECYCLE_UNAVAILABLE");
        Entry e=entries.get(port);
        if(e!=null && !e.key.isEmpty() && !e.key.equals(key))throw new IllegalStateException("I2P_IDENTITY_MISMATCH");
        if(e==null) { e=new Entry(port,key,State.WAITING);entries.put(port,e); }
        else if(e.key.isEmpty()) { Entry replacement=new Entry(port,key,e.state);entries.put(port,replacement);e=replacement; }
        if(e.references==0 && (e.state==State.WAITING||e.state==State.STARTING||e.state==State.RUNNING) && e.ready.isCompletedExceptionally()) {
            e.ready=new CompletableFuture<>();
            if(e.listenerObserved)e.ready.complete(null);
        }
        e.references++;return new Lease(e);
    }
    synchronized void tick() {
        if(closed||faulted)return;
        try {
            if(!applied())return;
            boolean changed=false;
            // Keep an allowance for native warm-up until CONNECT succeeds or the observation window elapses.
            for(Entry e:entries.values())if(e.state==State.STARTING && e.listenerObserved
                    && clock.getAsLong()-e.listenerReadyAt>=TimeUnit.SECONDS.toNanos(30))e.state=State.RUNNING;
            for(var iterator=entries.values().iterator();iterator.hasNext();) {
                Entry e=iterator.next();
                if(e.state==State.STOPPING) {
                    if(listening.applyAsInt(e.port)==0) {
                        e.listenerObserved=false; // A later activation must observe its own listener.
                        if(e.references==0)iterator.remove();
                        else { e.state=State.WAITING; }
                    }
                } else if(e.references==0 && (e.state==State.WAITING||e.state==State.FAILED)) iterator.remove();
                else if(e.references==0 && clock.getAsLong()-e.unusedSince>=cooldownNanos) {
                    e.state=State.STOPPING;e.ready=new CompletableFuture<>();changed=true;
                }
            }
            // Serialize native allocation/observation, not remote destination access.
            // Fresh telemetry plus per-warm-up allowances bound overlapping starts.
            boolean starting=entries.values().stream().anyMatch(e->e.state==State.STARTING && !e.listenerObserved);
            for(Entry e:entries.values()) if(!starting && e.state==State.WAITING && e.references>0 && freshAdmissionSample()) {
                if(!capacity.getAsBoolean()) { e.state=State.FAILED;e.ready.completeExceptionally(new IOException("I2P_CAPACITY_UNAVAILABLE"));continue; }
                // A port absent from the previous snapshot may still have a listener.
                // Only a recognized refusal permits publication; unknown remains WAITING.
                if(listening.applyAsInt(e.port)!=0)continue;
                e.state=State.STARTING;e.listenerObserved=false;nextAdmissionAfter=System.currentTimeMillis()/1000;starting=true;changed=true;
            }
            if(changed){publish();return;}
            for(Entry e:entries.values())if(e.state==State.STARTING && !e.listenerObserved && listening.applyAsInt(e.port)==1){e.listenerObserved=true;e.listenerReadyAt=clock.getAsLong();nextAdmissionAfter=System.currentTimeMillis()/1000;e.ready.complete(null);}
        } catch(Exception failure) {
            // Quarantine mutation after a publication error; the last native snapshot may differ.
            faulted=true;
            for(Entry e:entries.values())if(!e.ready.isDone())e.ready.completeExceptionally(new IOException("I2P_LIFECYCLE_UNAVAILABLE"));
        }
    }
    /** Ephemeral local state only: no identities, destinations, traffic counters or history. */
    synchronized void writeObservation() {
        Path temp=null;
        try {
            var process=ProcessHandle.current();
            StringBuilder json=new StringBuilder("{\"pid\":"+process.pid()+",\"startedAt\":\""+process.info().startInstant().orElseThrow()
                    +"\",\"observedAt\":\""+java.time.Instant.now()+"\",\"available\":"+(!closed&&!faulted&&applied())+",\"devices\":{");
            boolean first=true;
            for(Entry e:entries.values()) {
                String state=switch(e.state) {
                    case WAITING -> "WAITING";
                    case STOPPING -> "STOPPING";
                    case FAILED -> "UNAVAILABLE";
                    case STARTING, RUNNING -> e.references==0 ? "COOLDOWN" : e.connected>0 ? "CONNECTIONS_OPEN" : "STARTING";
                };
                if(!first)json.append(',');first=false;
                json.append('"').append(e.port).append("\":\"").append(state).append('"');
            }
            json.append("}}\n");
            temp=Files.createTempFile(directory,".status-",".json",PRIVATE);
            Files.writeString(temp,json);
            Files.move(temp,directory.resolve("status.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } catch(Exception ignored) { /* Observability cannot interrupt forwarding. Readers reject stale snapshots. */ }
        finally {if(temp!=null)try{Files.deleteIfExists(temp);}catch(IOException ignored){}}
    }
    private void publish() throws IOException {
        String next=UUID.randomUUID().toString().replace("-", "");
        StringBuilder text=new StringBuilder("[stargate-lifecycle]\ngeneration="+next+"\n\n");
        for(Entry e:entries.values())if(e.state==State.STARTING||e.state==State.RUNNING)
            text.append("[device-").append(e.key).append("]\ntype=socks\naddress=0.0.0.0\nport=").append(e.port)
                .append("\nkeys=device-").append(e.key).append(".dat\ninbound.length=3\noutbound.length=3\n\n");
        Path temp=Files.createTempFile(directory,".tunnels-",".tmp",PRIVATE);
        try {
            Files.writeString(temp,text);
            try(var file=FileChannel.open(temp,StandardOpenOption.WRITE)){file.force(true);}
            Files.move(temp,directory.resolve("tunnels.conf"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            try(var dir=FileChannel.open(directory,StandardOpenOption.READ)){dir.force(true);}
            generation=next;
        } finally {Files.deleteIfExists(temp);}
    }
    private int listening(int port) {
        try(var socket=new Socket()) {
            // Container service addresses may change after app startup or router recreation.
            var endpoint=new InetSocketAddress(router.getHostString(),port);
            if(endpoint.isUnresolved() || !(endpoint.getAddress().isLoopbackAddress() || endpoint.getAddress().isSiteLocalAddress()))return -1;
            socket.connect(endpoint,100);return 1;
        } catch(IOException failure) { return listenerFailure(failure); }
    }
    static int listenerFailure(IOException failure) {
        // Linux JDK in the application image reports this text for ECONNREFUSED.
        // Java exposes no errno here: messages are implementation/locale dependent,
        // so this is a conservative compatibility check, not an atomic reservation.
        return failure instanceof ConnectException && "Linux".equals(System.getProperty("os.name"))
                && "Connection refused (connect failed)".equals(failure.getMessage()) ? 0 : -1;
    }
    private boolean applied() {
        try {
            Path ack=directory.resolve("tunnels.conf.applied"), resources=directory.resolve("resources");
            if(Files.size(ack)>128||Files.size(resources)>256)return false;
            String[] r=Files.readString(resources).trim().split(" ");
            long age=System.currentTimeMillis()/1000-Long.parseLong(r[0]);
            return r.length==6&&age>=0&&age<=5&&Files.readString(ack).trim().equals(generation+" "+r[5]);
        }catch(Exception e){return false;}
    }
    private boolean freshAdmissionSample() {
        if(injectedCapacity)return true;
        try { return Long.parseLong(Files.readString(directory.resolve("resources")).split(" ")[0])>nextAdmissionAfter; }
        catch(Exception e){return false;}
    }
    private boolean capacity() {
        try {
            Path file=directory.resolve("resources");
            if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||Files.size(file)>256)return false;
            String[] fields=Files.readString(file).trim().split(" ");
            if(fields.length!=6)return false;
            long stamp=Long.parseLong(fields[0]),memory=Long.parseLong(fields[1]),maxMemory=Long.parseLong(fields[2]),tasks=Long.parseLong(fields[3]),maxTasks=Long.parseLong(fields[4]);
            long age=System.currentTimeMillis()/1000-stamp;
            long allowances=1+entries.values().stream().filter(e->e.state==State.STARTING).count();
            return age>=0&&age<=5&&Long.parseLong(fields[5])>0&&memory>=0&&tasks>=0&&maxMemory>=memory&&maxTasks>=tasks&&maxMemory-memory>=allowances*32L*1024*1024&&maxTasks-tasks>=allowances*16;
        } catch(Exception e){return false;}
    }
    @Override public void close() {
        synchronized(this){if(closed)return;closed=true;for(Entry e:entries.values())if(!e.ready.isDone())e.ready.completeExceptionally(new IOException("I2P_LIFECYCLE_STOPPED"));
            // ProxyServer closes all channels/event loops first. No live connection remains.
            entries.clear();try{publish();}catch(IOException ignored){}
        }
        worker.shutdownNow();writeObservation();
        try{worker.awaitTermination(3,TimeUnit.SECONDS);lock.release();ownership.close();}catch(Exception ignored){}

    }
}
