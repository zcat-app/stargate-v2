// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

/** Linux listener inode ownership; an unrelated HTTP responder cannot confirm startup. */
final class ListenerOwnership {
    static Boolean sample(Long pid, InetSocketAddress endpoint) {
        if (pid == null) return null;
        if (pid == 0) return false;
        Path process = Path.of("/proc", pid.toString());Set<String> sockets = new HashSet<>();
        try {
            try (var descriptors = Files.list(process.resolve("fd"))) {
                for (Path descriptor : descriptors.toList()) {
                    String link;
                    try { link = Files.readSymbolicLink(descriptor).toString(); }
                    catch (NoSuchFileException e) { continue; }
                    if (link.startsWith("socket:[") && link.endsWith("]")) sockets.add(link.substring(8, link.length() - 1));
                }
            }
            for (String family : new String[]{"tcp", "tcp6"}) {
                Path table = process.resolve("net").resolve(family);
                if (!Files.exists(table)) continue;
                try (var reader = Files.newBufferedReader(table)) {
                    reader.readLine();String line;
                    while ((line = reader.readLine()) != null) {
                        String[] fields = line.trim().split("\\s+");
                        if (fields.length < 10 || !fields[3].equals("0A") || !sockets.contains(fields[9])) continue;
                        String[] local = fields[1].split(":");
                        if (Integer.parseInt(local[1], 16) != endpoint.getPort()) continue;
                        byte[] address = HexFormat.of().parseHex(local[0]);
                        if (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN)
                            for (int i = 0; i < address.length; i += 4) {
                                byte a = address[i], b = address[i + 1];address[i] = address[i + 3];address[i + 1] = address[i + 2];address[i + 2] = b;address[i + 3] = a;
                            }
                        InetAddress bound = InetAddress.getByAddress(address);
                        if (bound.equals(endpoint.getAddress()) || (bound.isAnyLocalAddress()
                                && bound.getAddress().length == endpoint.getAddress().getAddress().length)) return true;
                    }
                }
            }
            return false;
        } catch (IOException | RuntimeException e) { return null; }
    }
}
