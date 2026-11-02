/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.*;
import java.util.*;

/** Linux read-only descriptors preserve the original NOFOLLOW/NONBLOCK plus fstat boundary. */
final class NativeInput implements AutoCloseable {
  private static final Linker LINKER = Linker.nativeLinker();
  private static final MethodHandle OPEN =
      LINKER.downcallHandle(
          LINKER.defaultLookup().find("open").orElseThrow(),
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
  private static final MethodHandle READ =
      LINKER.downcallHandle(
          LINKER.defaultLookup().find("read").orElseThrow(),
          FunctionDescriptor.of(
              ValueLayout.JAVA_LONG,
              ValueLayout.JAVA_INT,
              ValueLayout.ADDRESS,
              ValueLayout.JAVA_LONG));
  private static final MethodHandle CLOSE =
      LINKER.downcallHandle(
          LINKER.defaultLookup().find("close").orElseThrow(),
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
  private static final int FLAGS =
      04000 | 0400000 | 02000000; // O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
  private int fd;
  private final Arena arena;
  private final MemorySegment buffer;
  private final boolean singleLink;

  NativeInput(Path path, boolean singleLink) throws Exception {
    platform();
    this.singleLink = singleLink;
    try (var name = Arena.ofConfined()) {
      try {
        fd = (int) OPEN.invokeExact(name.allocateFrom(path.toString()), FLAGS);
      } catch (Throwable error) {
        throw new IOException("Input open failed: " + path, error);
      }
    }
    IO.need(fd >= 0, "Cannot open input without symlinks/nonblocking: " + path);
    Arena allocated = null;
    try {
      check();
      allocated = Arena.ofConfined();
      buffer = allocated.allocate(65536);
      arena = allocated;
    } catch (Exception error) {
      closeDescriptor();
      if (allocated != null) allocated.close();
      throw error;
    }
  }

  static void platform() throws IOException {
    IO.need(
        System.getProperty("os.name").equals("Linux")
            && ValueLayout.ADDRESS.byteSize() == 8
            && Set.of("amd64", "x86_64", "aarch64").contains(System.getProperty("os.arch")),
        "Supported Linux 64-bit descriptor ABI required");
  }

  Map<String, Object> info() throws IOException {
    return Files.readAttributes(Path.of("/proc/self/fd/" + fd), "unix:mode,uid,nlink,size,ino,dev");
  }

  void check() throws IOException {
    var info = info();
    int mode = ((Number) info.get("mode")).intValue();
    IO.need(
        (mode & 0170000) == 0100000
            && (!singleLink || ((Number) info.get("nlink")).longValue() == 1),
        "Regular" + (singleLink ? " single-link" : "") + " opened input required");
  }

  int read(byte[] destination) throws IOException {
    int count = Math.min(destination.length, 65536);
    long result;
    try {
      result = (long) READ.invokeExact(fd, buffer, (long) count);
    } catch (Throwable error) {
      throw new IOException("Input descriptor read failed", error);
    }
    IO.need(result >= 0 && result <= count, "Input descriptor read failed");
    if (result == 0) return -1;
    MemorySegment.copy(buffer, ValueLayout.JAVA_BYTE, 0, destination, 0, (int) result);
    return (int) result;
  }

  private void closeDescriptor() throws IOException {
    int owned = fd;
    fd = -1;
    if (owned >= 0)
      try {
        int status = (int) CLOSE.invokeExact(owned);
        IO.need(status == 0, "Input descriptor close failed");
      } catch (Throwable error) {
        if (error instanceof IOException io) throw io;
        throw new IOException("Input descriptor close failed", error);
      }
  }

  public void close() throws IOException {
    try {
      closeDescriptor();
    } finally {
      arena.close();
    }
  }
}
