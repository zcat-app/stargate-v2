/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import sun.misc.Signal;
import sun.misc.SignalHandler;

/** Signal handlers only request cancellation; the worker performs ownership-checked cleanup. */
final class Cancellation implements AutoCloseable {
    static final class Cancelled extends IOException { Cancelled() { super("Operation cancelled; completing owned-resource cleanup"); } }
    private static final ThreadLocal<Cancellation> CURRENT = new ThreadLocal<>();
    private final Thread worker;
    private final AtomicBoolean requested = new AtomicBoolean();
    private final AtomicInteger signal = new AtomicInteger();
    private final CountDownLatch completed = new CountDownLatch(1);
    private final Map<Signal, SignalHandler> handlers = new LinkedHashMap<>();
    private final Thread hook;
    private int cleanupDepth;

    private Cancellation(Thread worker) {
        this.worker = worker;
        hook = new Thread(() -> {
            request(0);
            boolean interrupted = false;
            for (;;) {
                try { completed.await(); break; }
                catch (InterruptedException ignored) { interrupted = true; }
            }
            if (interrupted) Thread.currentThread().interrupt();
        }, "libc-cancellation-shutdown");
    }
    static Cancellation install() {
        Cancellation context = new Cancellation(Thread.currentThread());
        Runtime.getRuntime().addShutdownHook(context.hook);
        try {
            for (String name : new String[]{"INT", "TERM"}) {
                Signal signal = new Signal(name);
                context.handlers.put(signal, Signal.handle(signal, value -> context.request(value.getNumber())));
            }
            CURRENT.set(context);
            return context;
        } catch (RuntimeException error) { context.close(); throw error; }
    }
    private synchronized void request(int number) {
        if (number != 0) signal.compareAndSet(0, number);
        if (requested.compareAndSet(false, true) && cleanupDepth == 0) worker.interrupt();
    }
    static void checkpoint() throws Cancelled {
        Cancellation context = CURRENT.get();
        if (context != null && context.cleanupDepth == 0 && context.requested.get()) throw new Cancelled();
    }
    static boolean cleaning() { Cancellation context = CURRENT.get(); return context != null && context.cleanupDepth > 0; }
    static Cleanup cleanup() {
        Cancellation context = CURRENT.get();
        // A pending interrupt must not immediately abort the ownership inspection or unmount.
        boolean interrupted;
        if (context == null) interrupted = Thread.interrupted();
        else synchronized (context) {
            interrupted = Thread.interrupted();
            context.cleanupDepth++;
        }
        return new Cleanup(context, interrupted);
    }
    static final class Cleanup implements AutoCloseable {
        private final Cancellation context; private final boolean interrupted;
        Cleanup(Cancellation context, boolean interrupted) { this.context = context; this.interrupted = interrupted; }
        public void close() {
            if (context != null) synchronized (context) {
                context.cleanupDepth--;
                if (context.cleanupDepth == 0 && context.requested.get()) context.worker.interrupt();
            }
            if (interrupted) Thread.currentThread().interrupt();
        }
    }
    int exitCode(int otherwise) { return signal.get() == 0 ? (requested.get() ? 1 : otherwise) : 128 + signal.get(); }
    public void close() {
        CURRENT.remove();
        completed.countDown();
        for (var entry : handlers.entrySet()) Signal.handle(entry.getKey(), entry.getValue());
        try { Runtime.getRuntime().removeShutdownHook(hook); }
        catch (IllegalStateException ignored) { /* shutdown is waiting on completed */ }
    }
}
