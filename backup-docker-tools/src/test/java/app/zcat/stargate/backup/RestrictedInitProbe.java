// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;

/** Run only in a dedicated container with an empty private /dest tmpfs. */
public final class RestrictedInitProbe {
    private RestrictedInitProbe() {}
    public static void main(String[] args) throws Exception {
        if (args.length != 0 || Linux.uid("getuid") != 0 || Linux.uid("geteuid") != 0
                || Linux.uid("getgid") != 0 || Linux.uid("getegid") != 0) throw new AssertionError("root required");
        String caps = Files.readAllLines(Path.of("/proc/self/status")).stream()
                .filter(line -> line.startsWith("CapEff:"))
                .map(line -> line.substring(7).trim()).findFirst().orElseThrow();
        if (!new BigInteger(caps, 16).equals(BigInteger.ONE)) throw new AssertionError("only CAP_CHOWN permitted");
        Path parent = Path.of("/dest");
        int fd = Linux.openDir(parent.toString(), false, 0);
        try {
            Linux.Stat stat = Linux.stat(fd);
            if (!VolumeSnapshot.directory(stat) || stat.uid() != 0 || stat.gid() != 0
                    || (stat.mode() & 07777) != 0700 || !VolumeSnapshot.names(fd).isEmpty())
                throw new AssertionError("empty private /dest required");
        } finally { Linux.close(fd); }
        List<String> roles = DockerPolicy.roots(true);
        for (String role : roles) Files.createDirectory(parent.resolve(role));
        InitRoots.main(roles.toArray(String[]::new));
        for (String role : roles) {
            var attributes = Files.readAttributes(parent.resolve(role), "unix:uid,gid,mode", LinkOption.NOFOLLOW_LINKS);
            if (((Number) attributes.get("uid")).intValue() != 10001
                    || ((Number) attributes.get("gid")).intValue() != 10001
                    || (((Number) attributes.get("mode")).intValue() & 07777) != 0700)
                throw new AssertionError("wrong initialized root: " + role);
        }
        System.out.println("RESTRICTED_INIT_REGRESSION_PASSED");
    }
}
