/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.compress.archivers.tar.*;
import org.tukaani.xz.*;

final class TestFiles {
  record Entry(String name, byte[] data, int mode, String link) {}

  static void tar(Path path, List<Entry> entries, boolean compressed) throws Exception {
    OutputStream stream = Files.newOutputStream(path);
    if (compressed) stream = new XZOutputStream(stream, new LZMA2Options());
    try (var out = new TarArchiveOutputStream(stream)) {
      out.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
      for (Entry entry : entries) {
        TarArchiveEntry item =
            entry.link == null
                ? new TarArchiveEntry(entry.name)
                : new TarArchiveEntry(entry.name, TarConstants.LF_SYMLINK);
        item.setMode(entry.mode);
        if (entry.link != null) item.setLinkName(entry.link);
        else item.setSize(entry.data.length);
        out.putArchiveEntry(item);
        if (entry.link == null && !item.isDirectory()) out.write(entry.data);
        out.closeArchiveEntry();
      }
    }
  }

  static byte[] xz(byte[] data) throws Exception {
    var output = new ByteArrayOutputStream();
    try (var compressed = new XZOutputStream(output, new LZMA2Options())) {
      compressed.write(data);
    }
    return output.toByteArray();
  }

  static Entry file(String name, byte[] data) {
    return new Entry(name, data, 0644, null);
  }

  static Entry dir(String name) {
    return new Entry(name.endsWith("/") ? name : name + "/", new byte[0], 0755, null);
  }
}
