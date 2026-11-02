// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.EdECPrivateKey;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OfflineI2pIdentityRecoveryTest {
    @TempDir Path root;
    Path app, data, control, expected, source, target;
    byte[] key;
    static final String OLD = "old", NEW = "fresh", TOKEN = "a".repeat(43);
    static final String CONFIG = "isolation.key=" + "01".repeat(32) + "\ni2p.deviceIsolation=true\ni2p.nextPort=14448\n"
            + "profile.fresh.token=" + TOKEN + "\nprofile.fresh.i2pPort=14447\n";

    void fixture() throws Exception {
        app = dir("app"); data = dir("data"); control = dir("control"); expected = root.resolve("expected");
        write(app.resolve("proxy.properties"), CONFIG.getBytes()); write(app.resolve("proxy-desired"), "stopped\n".getBytes());
        write(app.resolve("admin-token"), ("z".repeat(43)+"\n").getBytes());
        key = key(); source = data.resolve(name(OLD)); target = data.resolve(name(NEW)); write(source, key);
        write(expected, (b32(MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(key, 391))) + ".b32.i2p\n").getBytes());
    }
    Path dir(String n) throws Exception { Path p = Files.createDirectory(root.resolve(n)); Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwx------")); return p; }
    void write(Path p, byte[] bytes) throws Exception { Files.write(p, bytes); Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------")); }
    static String name(String id) throws Exception { return "device-" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(id.getBytes())) + ".dat"; }
    static String b32(byte[] a) { String alphabet="abcdefghijklmnopqrstuvwxyz234567"; StringBuilder b=new StringBuilder(); int n=0,v=0;for(byte x:a){v=(v<<8)|(x&255);n+=8;while(n>=5){n-=5;b.append(alphabet.charAt((v>>>n)&31));}}if(n>0)b.append(alphabet.charAt((v<<(5-n))&31));return b.toString(); }
    static byte[] key() throws Exception {
        var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); byte[] k = new byte[679]; new SecureRandom().nextBytes(k);
        byte[] pub = pair.getPublic().getEncoded(); System.arraycopy(pub, pub.length - 32, k, 352, 32);
        System.arraycopy(new byte[]{5,0,4,0,7,0,0}, 0, k, 384, 7);
        System.arraycopy(((EdECPrivateKey)pair.getPrivate()).getBytes().orElseThrow(), 0, k, 647, 32); return k;
    }
    void run(OfflineI2pIdentityRecovery.IO io) throws Exception { OfflineI2pIdentityRecovery.reassociate(app,data,control,OLD,NEW,expected,io); }
    void run() throws Exception { run(new OfflineI2pIdentityRecovery.IO()); }

    @Test void transfersOnlyKeyAndPreservesFreshCredentialAndCounter() throws Exception {
        fixture(); byte[] before = Files.readAllBytes(app.resolve("proxy.properties")); run();
        assertFalse(Files.exists(source)); assertArrayEquals(key, Files.readAllBytes(target));
        assertArrayEquals(before, Files.readAllBytes(app.resolve("proxy.properties")));
        assertEquals("z".repeat(43)+"\n",Files.readString(app.resolve("admin-token")));
        assertEquals("14448", ProxyConfig.read(app.resolve("proxy.properties")).getProperty("i2p.nextPort"));
        assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }
    @Test void rejectsInvalidSigningAndUnsupportedFormat() throws Exception {
        byte[] k=key(); assertEquals(32, OfflineI2pIdentityRecovery.validate(k).length);
        byte[] corrupt=k.clone(); corrupt[647]^=1; assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.validate(corrupt));
        byte[] mismatch=k.clone(); mismatch[352]^=1; assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.validate(mismatch));
        byte[] zero=k.clone(); Arrays.fill(zero,647,679,(byte)0); assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.validate(zero));
        byte[] unsupported=k.clone(); unsupported[389]=1; assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.validate(unsupported));
        assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.validate(Arrays.copyOf(k,678)));
        assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.validate(Arrays.copyOf(k,680)));
    }
    @Test void refusesDuplicateFingerprintExistingTargetAndWrongDestinationBeforeMutation() throws Exception {
        fixture(); Path other=data.resolve(name("other"));write(other,key);assertThrows(Exception.class,this::run);
        Files.delete(other); write(target, key()); byte[] existing=Files.readAllBytes(target);assertThrows(Exception.class,this::run);assertArrayEquals(existing,Files.readAllBytes(target));
        Files.delete(target);write(expected, ("a".repeat(52)+".b32.i2p\n").getBytes()); assertThrows(Exception.class,this::run);
        assertTrue(Files.exists(source));assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }
    @Test void acceptsSupervisorEmptyAndLifecycleGenerationOnlyFleet() throws Exception {
        for (String fleet : new String[]{"", "[stargate-lifecycle]\ngeneration=" + "a".repeat(32) + "\n\n"}) {
            Path sub=Files.createDirectory(root.resolve("fleet"+fleet.length()));root=sub;fixture();
            write(control.resolve("tunnels.conf"),fleet.getBytes());run();assertArrayEquals(key,Files.readAllBytes(target));
            assertEquals(fleet,Files.readString(control.resolve("tunnels.conf")));root=sub.getParent();
        }
    }
    @Test void rejectsOrphanPortCollisionAndStaleFleet() throws Exception {
        fixture();write(app.resolve("proxy.properties"),(CONFIG+"profile.orphan.i2pPort=14447\n").getBytes());assertThrows(Exception.class,this::run);
        write(app.resolve("proxy.properties"),CONFIG.getBytes());write(control.resolve("tunnels.conf"),("[stargate-lifecycle]\ngeneration="+"a".repeat(32)+"\n\n[device-old]\ntype=socks\nkeys=device-old.dat\nport=14447\n").getBytes());assertThrows(Exception.class,this::run);
        assertTrue(Files.exists(source));assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }
    @Test void failuresAtEverySyncRetainGateAndExactRetryCompletes() throws Exception {
        for (int failure=1;failure<=5;failure++) {
            Path sub=Files.createDirectory(root.resolve("case"+failure)); root=sub; fixture(); final int at=failure;
            assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
                int calls;
                @Override void forceDirectory(Path p) throws IOException { if (++calls==at) throw new IOException("injected"); super.forceDirectory(p); }
            }));
            assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
            assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.reassociate(app,data,control,OLD,"different",expected,new OfflineI2pIdentityRecovery.IO()));
            run();assertArrayEquals(key,Files.readAllBytes(target));assertFalse(Files.exists(source));assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
            root=sub.getParent();
        }
    }
    @Test void rejectsActiveOldInvalidNewUnsafeFilesAndOtherRecoveryGate() throws Exception {
        fixture(); Path config=app.resolve("proxy.properties");
        write(config,(CONFIG+"profile.old.token="+"b".repeat(43)+"\nprofile.old.i2pPort=14446\n").getBytes()); assertThrows(Exception.class,this::run);
        write(config,CONFIG.replace("i2pPort=14447","i2pPort=0").getBytes()); assertThrows(Exception.class,this::run);
        write(config,CONFIG.getBytes()); Files.setPosixFilePermissions(source,PosixFilePermissions.fromString("rw-r--r--"));assertThrows(Exception.class,this::run);
        Files.setPosixFilePermissions(source,PosixFilePermissions.fromString("rw-------"));Path alias=data.resolve("alias");Files.createLink(alias,source);assertThrows(Exception.class,this::run);Files.delete(alias);
        write(app.resolve("recovery-incomplete"),"incomplete\n".getBytes());assertThrows(Exception.class,this::run);Files.delete(app.resolve("recovery-incomplete"));
        Files.delete(source);Files.createSymbolicLink(source,root.resolve("missing"));assertThrows(Exception.class,this::run);
        assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }

    @Test void incompleteImportCannotBeBypassedByIdentityRecovery() throws Exception {
        fixture(); Path marker = app.resolve("volume-import-incomplete");
        for (String kind : new String[]{"partial-file", "dangling-link"}) {
            if (kind.equals("partial-file")) write(marker, new byte[0]);
            else Files.createSymbolicLink(marker, root.resolve("missing"));
            assertThrows(Exception.class, this::run);
            assertArrayEquals(key, Files.readAllBytes(source));
            assertFalse(Files.exists(target));
            assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
            assertTrue(Files.exists(marker, LinkOption.NOFOLLOW_LINKS));
            Files.delete(marker);
        }
    }
    @Test void failuresBeforeLinkAndSourceRemovalCanResumeOnlySamePlan() throws Exception {
        fixture(); assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void link(Path t, Path s) throws IOException { throw new IOException("injected"); }
        }));
        assertTrue(Files.exists(source));assertFalse(Files.exists(target));assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
        assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void delete(Path p) throws IOException { if(p.equals(source))throw new IOException("injected");super.delete(p); }
        }));
        assertTrue(Files.isSameFile(source,target));run();assertFalse(Files.exists(source));assertArrayEquals(key,Files.readAllBytes(target));
    }
    @Test void corruptSourceSigningKeyFailsBeforeGate() throws Exception {
        fixture(); key[647]^=1;write(source,key);assertThrows(Exception.class,this::run);
        assertTrue(Files.exists(source));assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }
    @Test void resumedPlanResyncsGateBeforeAnyKeyMutation() throws Exception {
        fixture(); assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void forceDirectory(Path p) throws IOException { throw new IOException("injected"); }
        }));
        assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));assertFalse(Files.exists(target));
        assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void forceFile(Path p) throws IOException { if(p.getFileName().toString().equals(OfflineI2pIdentityRecovery.MARKER))throw new IOException("injected");super.forceFile(p); }
        }));
        assertTrue(Files.exists(source));assertFalse(Files.exists(target));run();assertArrayEquals(key,Files.readAllBytes(target));
    }
    @Test void retryMustSyncPublishedTargetBeforeRetiringSource() throws Exception {
        fixture();assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void link(Path t, Path s) throws IOException { super.link(t,s);throw new IOException("injected"); }
        }));
        assertTrue(Files.isSameFile(source,target));
        assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void forceDirectory(Path p) throws IOException { if(p.equals(data))throw new IOException("injected");super.forceDirectory(p); }
        }));
        assertTrue(Files.isSameFile(source,target));assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
        run();assertFalse(Files.exists(source));assertArrayEquals(key,Files.readAllBytes(target));
    }
    @Test void interruptionAfterLinkAndAfterUnlinkCanResume() throws Exception {
        fixture(); assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void link(Path t, Path s) throws IOException { super.link(t,s);throw new IOException("injected"); }
        }));
        assertTrue(Files.isSameFile(source,target));
        assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void delete(Path p) throws IOException { super.delete(p);if(p.equals(source))throw new IOException("injected"); }
        }));
        assertFalse(Files.exists(source));assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
        run();assertArrayEquals(key,Files.readAllBytes(target));
    }
    @Test void partialPreparingFileCanBeRetriedOnlyForSamePlan() throws Exception {
        fixture(); assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void createPreparing(Path p, byte[] content) throws IOException {
                Files.write(p, Arrays.copyOf(content, 30), StandardOpenOption.CREATE_NEW);
                Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));throw new IOException("injected");
            }
        }));
        assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.PREPARING)));
        assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
        assertTrue(Files.exists(source));assertFalse(Files.exists(target));
        assertThrows(Exception.class, () -> OfflineI2pIdentityRecovery.reassociate(app,data,control,"other",NEW,expected,new OfflineI2pIdentityRecovery.IO()));
        run();assertArrayEquals(key,Files.readAllBytes(target));assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.PREPARING)));
    }
    @Test void unrelatedPreparingFileIsNeverRemoved() throws Exception {
        fixture();Path p=app.resolve(OfflineI2pIdentityRecovery.PREPARING);write(p,"unrelated\n".getBytes());
        assertThrows(Exception.class,this::run);assertEquals("unrelated\n",Files.readString(p));assertTrue(Files.exists(source));assertFalse(Files.exists(target));
    }
    @Test void unsafePreparingAliasAndExistingTargetRemainGated() throws Exception {
        fixture();Path p=app.resolve(OfflineI2pIdentityRecovery.PREPARING);
        write(p,"I2P-IDENTITY-1\n".getBytes());Path alias=app.resolve("alias");Files.createLink(alias,p);
        assertThrows(Exception.class,this::run);assertTrue(Files.exists(p));assertFalse(Files.exists(target));
        Files.delete(alias);write(target,key());assertThrows(Exception.class,this::run);
        assertTrue(Files.exists(p));assertTrue(Files.exists(source));assertTrue(Files.exists(target));
    }
    @Test void wrongOrDanglingPreparingIsNotRetired() throws Exception {
        fixture();Path p=app.resolve(OfflineI2pIdentityRecovery.PREPARING);
        Files.createSymbolicLink(p,root.resolve("missing"));assertThrows(Exception.class,this::run);
        assertTrue(Files.isSymbolicLink(p));assertTrue(Files.exists(source));assertFalse(Files.exists(target));
    }
    @Test void interruptedFullPreparingWriteCanBeRetried() throws Exception {
        fixture();assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void createPreparing(Path p, byte[] content) throws IOException { super.createPreparing(p,content);throw new IOException("injected"); }
        }));
        assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.PREPARING)));assertFalse(Files.exists(target));
        run();assertArrayEquals(key,Files.readAllBytes(target));
    }
    @Test void publishedTwoNameGateResumesAfterInterruptedLink() throws Exception {
        fixture(); assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void publishMarker(Path marker, Path preparing) throws IOException { super.publishMarker(marker,preparing);throw new IOException("injected"); }
        }));
        Path marker=app.resolve(OfflineI2pIdentityRecovery.MARKER), preparing=app.resolve(OfflineI2pIdentityRecovery.PREPARING);
        assertTrue(Files.isSameFile(marker,preparing));assertTrue(Files.exists(source));assertFalse(Files.exists(target));
        run();assertArrayEquals(key,Files.readAllBytes(target));assertFalse(Files.exists(marker));assertFalse(Files.exists(preparing));
    }
    @Test void finalMarkerDeletionSyncFailureRestoresGateAndCanRetry() throws Exception {
        fixture();assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            int count;
            @Override void forceDirectory(Path p) throws IOException { if (++count == 5) throw new IOException("injected");super.forceDirectory(p); }
        }));
        Path marker=app.resolve(OfflineI2pIdentityRecovery.MARKER);
        assertTrue(Files.exists(marker));assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.PREPARING)));
        assertFalse(Files.exists(source));assertArrayEquals(key,Files.readAllBytes(target));
        run();assertFalse(Files.exists(marker));assertArrayEquals(key,Files.readAllBytes(target));
    }
    @Test void disabledProfileWithAllocatedPortIsAllowed() throws Exception {
        fixture();write(app.resolve("proxy.properties"),(CONFIG+"profile.fresh.i2pEnabled=false\n").getBytes());
        run();assertArrayEquals(key,Files.readAllBytes(target));
    }
    @Test void corruptOtherManagedKeyIsRejected() throws Exception {
        fixture(); byte[] other=key(); other[647]^=1;write(data.resolve(name("other")),other);
        assertThrows(Exception.class,this::run);assertTrue(Files.exists(source));assertFalse(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }
    @Test void ambiguousMarkerIsNeverCleared() throws Exception {
        fixture();assertThrows(Exception.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void link(Path t, Path s) throws IOException { super.link(t,s);Files.writeString(app.resolve(OfflineI2pIdentityRecovery.MARKER),"ambiguous\n"); }
        }));
        assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));assertThrows(Exception.class,this::run);
    }
    @Test void fleetIsRecheckedBeforeGateClear() throws Exception {
        fixture(); assertThrows(Exception.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void link(Path t, Path s) throws IOException { super.link(t,s);Files.writeString(control.resolve("tunnels.conf"),"[device-old]\nkeys=old.dat\n");Files.setPosixFilePermissions(control.resolve("tunnels.conf"),PosixFilePermissions.fromString("rw-------")); }
        }));
        assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }
    @Test void cliNeverPrintsSensitiveInputs() throws Exception {
        fixture(); var out=new java.io.ByteArrayOutputStream();var err=new java.io.ByteArrayOutputStream();
        int status=OfflineI2pIdentityRecovery.run(new String[]{"--staged-app",app.toString(),"--staged-i2p-data",data.toString(),"--staged-i2p-control",control.toString(),"--old-device",OLD,"--new-device",NEW,"--expected-b32-file",expected.toString(),"--ack-authorized-fresh-pair","--ack-all-copies-and-services-offline"},new java.io.PrintStream(out),new java.io.PrintStream(err));
        assertEquals(0,status);String output=out.toString()+err.toString();assertFalse(output.contains(OLD));assertFalse(output.contains(NEW));assertFalse(output.contains(TOKEN));assertFalse(output.contains(Files.readString(expected).trim()));
    }
    @Test void noReplaceRaceCannotAdoptUnrelatedTarget() throws Exception {
        fixture();byte[] unrelated=key();assertThrows(IOException.class, () -> run(new OfflineI2pIdentityRecovery.IO() {
            @Override void link(Path t, Path s) throws IOException { Files.write(t,unrelated); Files.setPosixFilePermissions(t,PosixFilePermissions.fromString("rw-------")); super.link(t,s); }
        }));
        assertArrayEquals(unrelated,Files.readAllBytes(target)); assertThrows(Exception.class,this::run);
        assertTrue(Files.exists(app.resolve(OfflineI2pIdentityRecovery.MARKER)));
    }
}
