/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import java.nio.file.Path;
import java.util.*;

public final class LibcTools {
    public static void main(String[] args) {
        System.exit(controlled(() -> execute(args, new LibcIO.Processes())));
    }
    @FunctionalInterface interface Work { int run() throws Exception; }
    static int controlled(Work work) {
        Cancellation cancellation = Cancellation.install();
        int status = 1;
        try { status = work.run(); Cancellation.checkpoint(); }
        catch (Exception failure) {
            System.err.println("Libc tools failed: " + failure.getMessage());
            for (Throwable cleanup : failure.getSuppressed()) System.err.println("Cleanup failed: " + cleanup.getMessage());
        } finally { cancellation.close(); }
        return cancellation.exitCode(status);
    }
    static int execute(String[] args, LibcIO.Runner runner) throws Exception {
        Cancellation.checkpoint();
        if (args.length == 1 && args[0].equals("--help")) { usage(); return 0; }
        LibcIO.need(args.length >= 3 && args[0].equals("--project"), "Expected --project ROOT diagnose|build|regression");
        LibcIO io = new LibcIO(Path.of(args[1]), runner); String kind = args[2];
        if (args.length == 4 && args[3].equals("--help")) { usage(); return 0; }
        if (kind.equals("diagnose")) { LibcIO.need(args.length == 3, "Diagnostic takes no options"); return new Diagnostic(io, Diagnostic::dockerAvailable).print(); }
        if (kind.equals("build")) {
            Map<String, String> values = new HashMap<>(); Set<String> known = Set.of("--fresh-builder-id", "--expected-image-id", "--builder-marker", "--output-dir");
            for (int i = 3; i < args.length; i++) { LibcIO.need(known.contains(args[i]) && i + 1 < args.length, "Unknown or incomplete build option: " + args[i]); String option = args[i]; LibcIO.need(!values.containsKey(option), "Duplicate option: " + option); values.put(option, args[++i]); }
            new LibcBuild(io).execute(new LibcBuild.Options(values.get("--fresh-builder-id"), values.get("--expected-image-id"), values.get("--builder-marker"), values.containsKey("--output-dir") ? Path.of(values.get("--output-dir")) : null)); return 0;
        }
        if (kind.equals("regression")) {
            String label = null; boolean compare = false; Path evidence = io.project.resolve("target/libc-regression"); List<Path> debs = new ArrayList<>();
            for (int i = 3; i < args.length; i++) {
                String option = args[i];
                if (option.equals("--compare")) compare = true;
                else if (option.equals("--label") && i + 1 < args.length) label = args[++i];
                else if (option.equals("--evidence-dir") && i + 1 < args.length) evidence = Path.of(args[++i]).toAbsolutePath();
                else if (option.equals("--libc-deb") && i + 1 < args.length && !args[i + 1].startsWith("--")) { while (i + 1 < args.length && !args[i + 1].startsWith("--")) debs.add(Path.of(args[++i]).toAbsolutePath()); }
                else throw new IllegalArgumentException("Unknown or incomplete regression option: " + option);
            }
            LibcIO.need(label != null, "Regression requires --label control|patched");
            return new FopenRegression(io).execute(label, debs, compare, evidence) ? 0 : 1;
        }
        throw new IllegalArgumentException("Unknown command: " + kind);
    }
    private static void usage() { System.out.println("Usage: libc-tools --project ROOT diagnose|build|regression\nBuild: [--fresh-builder-id FULL_ID --expected-image-id sha256:ID --builder-marker HEX32 --output-dir NEW_ABSOLUTE_PATH]\nRegression: --label control|patched [--libc-deb PATH ...] [--compare] [--evidence-dir PATH]\nDefault build uses the separately prepared stargate-v2-libc-build container. Source/seed/bootstrap preparation is a separate migration."); }
}
