// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

/** Defer interruption while a known helper is being reconciled and removed. */
final class Cancellation {
    interface Action { void run() throws Exception; }
    private final Thread worker; private boolean requested, cleaning;
    Cancellation(Thread worker) { this.worker=worker; }
    synchronized void request() {requested=true;if(!cleaning)worker.interrupt();}
    synchronized void check() throws InterruptedException {if(requested||worker.isInterrupted())throw new InterruptedException();}
    void cleanup(Action action) throws Exception {
        boolean interrupted;
        synchronized(this){cleaning=true;interrupted=Thread.interrupted();}
        try{action.run();}
        finally{synchronized(this){cleaning=false;if(interrupted||requested)worker.interrupt();}}
    }
}
