// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Full native age authentication into a held private spool; no header is inspected here. */
final class AgeDecrypt {
    private static final long MAX_BINARY = 32L * 1024 * 1024;
    private static final AtomicInteger CHILD = new AtomicInteger(-1);
    static final class Uncertain extends IOException { Uncertain(Throwable cause) { super("Age process outcome uncertain", cause); } }
    private AgeDecrypt() {}
    static void decrypt(Path executable, String expectedHash, Path identity, int ciphertext, int output, int uid) throws Exception {
        try(Session age=open(executable,expectedHash,identity,uid)){age.decrypt(ciphertext,output);}
    }
    static void encrypt(Path executable, String expectedHash, Path identity, int plaintext, int output, int uid, String recipient) throws Exception {
        try(Session age=open(executable,expectedHash,identity,uid)){age.encrypt(plaintext,output,recipient);}
    }
    static Session open(Path executable, String expectedHash, Path identity, int uid) throws Exception {
        if (!expectedHash.matches("[0-9a-f]{64}")) throw DockerPolicy.failure();
        int binary = Linux.openRegular(DurableJournal.safePath(executable.toString()), MAX_BINARY, false, uid);
        try {
            Linux.Stat before = Linux.stat(binary);
            if ((before.uid() != 0 && before.uid() != Integer.toUnsignedLong(uid)) || (before.mode() & 06022) != 0 || (before.mode() & 0111) == 0
                    || !expectedHash.equals(binaryHash(binary)) || !before.equals(Linux.stat(binary))) throw DockerPolicy.failure();
            int key = Linux.openRegular(DurableJournal.safePath(identity.toString()), 65536, true, uid);
            try { checkIdentity(key); return new Session(binary,key); }
            catch(Exception e) {Linux.close(key);throw e;}
        } catch(Exception e) {Linux.close(binary);throw e;}
    }
    static final class Session implements AutoCloseable {
        private final int binary,key;
        Session(int binary,int key){this.binary=binary;this.key=key;}
        void encrypt(int input,int output,String recipient)throws Exception {
            if(recipient==null||!recipient.matches("age1[0-9a-z]{58}"))throw DockerPolicy.failure();run(binary,key,input,output,recipient);
        }
        void decrypt(int input,int output)throws Exception {run(binary,key,input,output,null);}
        public void close() throws IOException {
            IOException failure=null;try{Linux.close(key);}catch(IOException e){failure=e;}try{Linux.close(binary);}catch(IOException e){if(failure==null)failure=e;else failure.addSuppressed(e);}
            if(failure!=null)throw failure;
        }
    }
    private static String binaryHash(int fd) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); byte[] buffer = new byte[65536]; long total = 0;
        try (InputStream in = Files.newInputStream(Linux.fdPath(fd))) {
            byte[] magic = in.readNBytes(4); if (!Arrays.equals(magic,new byte[]{0x7f,'E','L','F'})) throw DockerPolicy.failure();
            hash.update(magic); total = 4; int n;
            while ((n = in.read(buffer)) != -1) { total += n; if (total > MAX_BINARY) throw DockerPolicy.failure(); hash.update(buffer,0,n); }
        }
        return HexFormat.of().formatHex(hash.digest());
    }
    private static void checkIdentity(int fd) throws IOException {
        byte[] content; try (InputStream in = Files.newInputStream(Linux.fdPath(fd))) { content = in.readNBytes(65537); }
        try {
            if (content.length > 65536) throw DockerPolicy.failure(); for (byte b : content) if (b < 0) throw DockerPolicy.failure();
            String key = null; for (String line : new String(content,StandardCharsets.US_ASCII).split("\\r\\n|[\\n\\r\\u000b\\u000c\\u001c-\\u001e]",-1)) {
                if (!line.isEmpty() && !line.startsWith("#")) { if (key != null) throw DockerPolicy.failure(); key = line; }
            }
            if (key == null || !key.matches("AGE-SECRET-KEY-1[0-9A-Z]{58}")) throw DockerPolicy.failure();
        } finally { Arrays.fill(content,(byte)0); }
    }
    private static void run(int binary, int key, int input, int output, String recipient) throws Exception {
        boolean reaped = false; int pid = -1;
        try (Arena arena = Arena.ofConfined()) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
            Linux.seekStart(input); Linux.seekStart(key); Linux.seekStart(output); pid = Linux.spawnAge(binary,key,input,output,CHILD,recipient);
            long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(30); var status = arena.allocate(ValueLayout.JAVA_INT);
            while (true) {
                if (Thread.currentThread().isInterrupted() || System.nanoTime() - deadline >= 0) throw new InterruptedException();
                if (Linux.waitNoHang(pid,status) == pid) {
                    reaped = true; CHILD.set(-1); if (status.get(ValueLayout.JAVA_INT,0) != 0) throw new IOException("Authentication failed"); break;
                }
                Thread.sleep(50);
            }
            Linux.sync(output); if (Linux.stat(output).size() > ArchiveInspector.MAX_ARCHIVE + (recipient == null ? 0 : 32L*1024*1024)) throw DockerPolicy.failure(); Linux.seekStart(output);
        } finally {
            int child = CHILD.get();
            if (!reaped && child > 0) {
                try { Linux.kill(child); } catch (IOException ignored) { }
                try { Linux.waitForDeath(child); CHILD.set(-1); } catch (IOException failure) { throw new Uncertain(failure); }
            }
        }
    }
}
