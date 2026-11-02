/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.io.IOException;
import static app.zcat.stargate.libc.LibcIO.*;

/** Keep new regression output out of source trees, unrelated directories, and aliases. */
final class RegressionEvidence {
    static final String MARKER = ".stargate-libc-regression", CONTENT = "stargate-libc-regression-v1\n";
    static Path prepare(Path project, Path proposed) throws Exception {
        Path path = proposed.toAbsolutePath().normalize();
        need(!path.equals(path.getRoot()) && !path.equals(project) && (!path.startsWith(project) || path.startsWith(project.resolve("target"))), "Regression evidence must be outside source directories");
        for (Path current = path; current != null; current = current.getParent()) if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) need(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS), "Evidence parent is symbolic or not a directory");
        if (Files.exists(path)) {
            Path marker = path.resolve(MARKER);
            boolean empty; try (var entries = Files.list(path)) { empty = entries.findAny().isEmpty(); }
            need(empty || (Files.isRegularFile(marker, LinkOption.NOFOLLOW_LINKS) && Files.readString(marker).equals(CONTENT)), "Existing evidence directory is not an owned libc regression directory");
        } else Files.createDirectories(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
        Path marker = path.resolve(MARKER);
        if (!Files.exists(marker, LinkOption.NOFOLLOW_LINKS)) Files.writeString(marker, CONTENT, StandardOpenOption.CREATE_NEW);
        return path;
    }
    static Path logs(Path evidence, String label) throws Exception {
        Path path = evidence.resolve("valgrind-logs-" + label).resolve("regress-" + label);
        for (Path current = path; !current.equals(evidence); current = current.getParent()) if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) need(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS), "Regression log directory is symbolic or not a directory");
        Files.createDirectories(path); return path;
    }
    static void write(Path file, byte[] bytes) throws IOException {
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) need(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && ((Number)Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).longValue() == 1, "Regression evidence file is linked or not regular");
        Files.write(file, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
    }
}
