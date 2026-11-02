// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

/** Operator-invoked controller. It never removes an uncertain Docker resource. */
public final class DockerImportMain {
    private DockerImportMain() {}
    public static void main(String[] args) {
        Thread caller = Thread.currentThread(); CountDownLatch finished = new CountDownLatch(1);
        Thread hook = new Thread(() -> { caller.interrupt(); try { finished.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }, "docker-import-cleanup");
        Runtime.getRuntime().addShutdownHook(hook);
        int code;
        try { code = run(args); } finally { finished.countDown(); }
        try { Runtime.getRuntime().removeShutdownHook(hook); } catch (IllegalStateException e) { return; }
        System.exit(code);
    }
    static int run(String[] args) {
        Map<String,String> values = new HashMap<>(); boolean nym = false, ack = false;
        Set<String> names = Set.of("--source", "--journal-dir", "--helper-image", "--core-jar", "--adapter-jar");
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--nym") && !nym) { nym = true; continue; }
            if (args[i].equals("--ack-exclusive-local-daemon") && !ack) { ack = true; continue; }
            String name = args[i]; if (!names.contains(name) || values.containsKey(name) || ++i >= args.length) return usage();
            values.put(name, args[i]);
        }
        if (!ack || !values.keySet().equals(names)) return usage();
        String location = "unavailable";
        try {
            if (!"Linux".equals(System.getProperty("os.name"))) throw DockerPolicy.failure();
            int uid = Linux.uid("getuid"), euid = Linux.uid("geteuid"), gid = Linux.uid("getgid"), egid = Linux.uid("getegid");
            if (euid == 0 || uid != euid || gid != egid) throw DockerPolicy.failure();
            String image = values.get("--helper-image"); DockerPolicy.imageId(image);
            Path source = DurableJournal.safePath(values.get("--source")), journalDir = DurableJournal.safePath(values.get("--journal-dir"));
            Path core = DurableJournal.safePath(values.get("--core-jar")), adapter = DurableJournal.safePath(values.get("--adapter-jar"));
            byte[] nonce = new byte[16]; new SecureRandom().nextBytes(nonce); String token = HexFormat.of().formatHex(nonce);
            try (DurableJournal journal = new DurableJournal(journalDir, "stargate-import-", token, euid, egid)) {
                location = journal.path.toString();
                try (PinnedInputs inputs = new PinnedInputs(source, journalDir, token, core, adapter, 10001, 10001, euid, egid)) {
                    DockerImport.Plan plan = new DockerImport.Plan(token, image, source.toString(), inputs.core.toString(), inputs.adapter.toString(), inputs.hashes(), nym);
                    DockerImport.run(plan, new DockerTransport.ProcessClient("docker"), journal::record, inputs);
                } catch (Exception failure) {
                    try { journal.record("failed_or_interrupted", Map.of("instruction", "Keep offline; retain and inspect every planned resource. Do not retry into these volumes.")); }
                    catch (Exception ignored) { }
                    throw failure;
                }
            }
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
            System.out.println("OFFLINE_DOCKER_IMPORT_CREATED_RECOVERY_REQUIRED; private journal: " + location); return 0;
        } catch (Exception failure) {
            System.err.println("IMPORT FAILED: keep all copies offline; inspect the private journal and planned resources: " + location); return 1;
        }
    }
    private static int usage() {
        System.err.println("Requires --source DIR --journal-dir DIR --helper-image sha256:ID --core-jar FILE --adapter-jar FILE [--nym] --ack-exclusive-local-daemon"); return 2;
    }
}
