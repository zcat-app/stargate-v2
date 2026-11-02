// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Focused offline tests. Compile with SyncTlsCertificate.java; no external Java dependencies. */
public final class TestSyncTlsCertificate {
    static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    interface Action { void run() throws Exception; }
    static void rejects(Action action) throws Exception {
        try { action.run(); } catch (Exception expected) { return; }
        throw new AssertionError("invalid input was accepted");
    }
    static void openssl(String... args) throws Exception {
        var command = new ArrayList<String>(); command.add("/usr/bin/openssl"); command.addAll(List.of(args));
        var process = new ProcessBuilder(command).redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try { check(process.waitFor(15, TimeUnit.SECONDS) && process.exitValue() == 0, "fixture generation failed"); }
        finally { process.destroyForcibly(); }
    }
    static void generate(Path root, String name, String algorithm) throws Exception {
        var args = new ArrayList<>(List.of("req", "-x509", "-newkey"));
        if (algorithm.equals("EC")) args.addAll(List.of("ec", "-pkeyopt", "ec_paramgen_curve:P-256"));
        else args.add(algorithm);
        args.addAll(List.of("-nodes", "-keyout", root.resolve(name + ".key").toString(), "-out",
                root.resolve(name + ".crt").toString(), "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"));
        openssl(args.toArray(String[]::new));
        Files.setPosixFilePermissions(root.resolve(name + ".key"), SyncTlsCertificate.PRIVATE);
    }
    static SyncTlsCertificate.Result sync(Path root, String certificate, String key, Path output) throws Exception {
        return SyncTlsCertificate.sync(root.resolve(certificate + ".crt"), root.resolve(key + ".key"), output,
                SyncTlsCertificate.currentUid());
    }
    static Map<String,String> state(Path output) throws Exception {
        var result = new TreeMap<String,String>();
        try (var entries = Files.list(output)) {
            for (Path entry : entries.toList()) result.put(entry.getFileName().toString(),
                    HexFormat.of().formatHex(Files.readAllBytes(entry)) + Files.getPosixFilePermissions(entry));
        }
        return result;
    }
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("stargate-java-tls-sync-");
        int passed = 0;
        try {
            generate(root,"ec1","EC"); generate(root,"ec2","EC"); generate(root,"rsa","rsa:2048");
            Path output = root.resolve("deployment");
            check(sync(root,"ec1","ec1",output).changed(),"initial stage must change");
            check(Files.readString(output.resolve("server.key")).startsWith("-----BEGIN PRIVATE KEY-----"),"PKCS8 required");
            check(Files.getPosixFilePermissions(output).equals(SyncTlsCertificate.DIRECTORY),"directory mode");
            check(Files.getPosixFilePermissions(output.resolve("server.key")).equals(SyncTlsCertificate.PRIVATE),"private key mode");
            Object inode=Files.getAttribute(output.resolve("server.key"),"unix:ino");
            check(!sync(root,"ec1","ec1",output).changed(),"second stage must be no-op");
            check(inode.equals(Files.getAttribute(output.resolve("server.key"),"unix:ino")),"no-op must preserve inode");passed++;

            var before=state(output);
            rejects(()->sync(root,"ec1","ec2",output));check(before.equals(state(output)),"mismatch changed deployment");
            Files.writeString(root.resolve("malformed.crt"),"not a certificate");
            rejects(()->sync(root,"malformed","ec1",output));
            openssl("x509","-in",root.resolve("ec1.crt").toString(),"-signkey",root.resolve("ec1.key").toString(),"-days","-1","-out",root.resolve("expired.crt").toString());
            rejects(()->sync(root,"expired","ec1",output));
            Files.write(root.resolve("oversized.crt"),new byte[65537]);rejects(()->sync(root,"oversized","ec1",output));
            Files.setPosixFilePermissions(root.resolve("ec1.key"),PosixFilePermissions.fromString("rw-r-----"));
            rejects(()->sync(root,"ec1","ec1",output));Files.setPosixFilePermissions(root.resolve("ec1.key"),SyncTlsCertificate.PRIVATE);
            check(before.equals(state(output)),"invalid input changed bytes or permissions");passed++;

            boolean[] rotated={false};
            rejects(()->SyncTlsCertificate.sync(root.resolve("ec1.crt"),root.resolve("ec1.key"),output,SyncTlsCertificate.currentUid(),(path,secret)->{
                byte[] bytes=SyncTlsCertificate.snapshot(path,secret);
                if(!secret&&!rotated[0]){Files.copy(root.resolve("ec2.crt"),root.resolve("ec1.crt"),StandardCopyOption.REPLACE_EXISTING);Files.copy(root.resolve("ec2.key"),root.resolve("ec1.key"),StandardCopyOption.REPLACE_EXISTING);Files.setPosixFilePermissions(root.resolve("ec1.key"),SyncTlsCertificate.PRIVATE);rotated[0]=true;}
                return bytes;
            }));check(rotated[0]&&before.equals(state(output)),"issuer rotation mixed snapshots or mutated deployment");
            check(sync(root,"ec1","ec1",output).changed(),"matching rotation did not recover");passed++;

            check(sync(root,"rsa","rsa",output).changed(),"RSA pair rejected");
            openssl("rsa","-in",root.resolve("rsa.key").toString(),"-traditional","-out",root.resolve("traditional.key").toString());
            Files.setPosixFilePermissions(root.resolve("traditional.key"),SyncTlsCertificate.PRIVATE);
            check(!sync(root,"rsa","traditional",output).changed(),"PKCS1 conversion should preserve canonical PKCS8");passed++;

            Files.setPosixFilePermissions(output.resolve("server.key"),PosixFilePermissions.fromString("rw-r-----"));
            check(!sync(root,"rsa","rsa",output).changed(),"permission repair is not certificate change");
            check(Files.getPosixFilePermissions(output.resolve("server.key")).equals(SyncTlsCertificate.PRIVATE),"permissions not repaired");passed++;

            Path victim=root.resolve("victim");Files.writeString(victim,"untouched");var mode=Files.getPosixFilePermissions(victim);
            Files.delete(output.resolve("server.crt"));Files.createSymbolicLink(output.resolve("server.crt"),victim);
            rejects(()->sync(root,"rsa","rsa",output));check(Files.readString(victim).equals("untouched")&&Files.getPosixFilePermissions(victim).equals(mode),"symlink target changed");
            Files.delete(output.resolve("server.crt"));sync(root,"rsa","rsa",output);
            Path alias=root.resolve("output-alias");Files.createSymbolicLink(alias,output);rejects(()->sync(root,"rsa","rsa",alias));
            Files.setPosixFilePermissions(output,PosixFilePermissions.fromString("rwxrwx---"));rejects(()->sync(root,"rsa","rsa",output));Files.setPosixFilePermissions(output,SyncTlsCertificate.DIRECTORY);passed++;

            Path directTemporary=Files.createTempDirectory("stargate-tls-untrusted-parent-");
            try { rejects(()->sync(root,"rsa","rsa",directTemporary));check(Files.list(directTemporary).findAny().isEmpty(),"writable-parent rejection changed directory"); }
            finally { Files.delete(directTemporary); }

            Path certLink=root.resolve("issuer.crt"),keyLink=root.resolve("issuer.key");Files.createSymbolicLink(certLink,root.resolve("rsa.crt"));Files.createSymbolicLink(keyLink,root.resolve("rsa.key"));
            check(!SyncTlsCertificate.sync(certLink,keyLink,output,SyncTlsCertificate.currentUid()).changed(),"issuer symlinks not supported");passed++;

            generate(root,"unsupported","ed25519");before=state(output);rejects(()->sync(root,"unsupported","unsupported",output));check(before.equals(state(output)),"unsupported key changed deployment");passed++;
            System.out.println("PASS: "+passed+" focused certificate-sync cases (RSA/EC, conversion, snapshot race, refusal boundaries, permissions and no-op).");
        } finally {
            try(var files=Files.walk(root)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}
        }
    }
}
