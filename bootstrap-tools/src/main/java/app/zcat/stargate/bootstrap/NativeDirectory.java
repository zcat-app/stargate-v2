/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.channels.FileChannel;
import java.nio.file.*;

/** Linux directory descriptors anchor private fence/journal creation and directory fsync. */
final class NativeDirectory implements AutoCloseable {
  private static final Linker LINKER = Linker.nativeLinker();
  private static final MethodHandle OPEN =
      LINKER.downcallHandle(
          LINKER.defaultLookup().find("open").orElseThrow(),
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
  private static final MethodHandle OPENAT =
      LINKER.downcallHandle(
          LINKER.defaultLookup().find("openat").orElseThrow(),
          FunctionDescriptor.of(
              ValueLayout.JAVA_INT,
              ValueLayout.JAVA_INT,
              ValueLayout.ADDRESS,
              ValueLayout.JAVA_INT,
              ValueLayout.JAVA_INT),
          Linker.Option.firstVariadicArg(3));
  private static final MethodHandle FSYNC =
      LINKER.downcallHandle(
          LINKER.defaultLookup().find("fsync").orElseThrow(),
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
  private static final MethodHandle CLOSE =
      LINKER.downcallHandle(
          LINKER.defaultLookup().find("close").orElseThrow(),
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
  private static final int DIRECTORY = 0200000 | 0400000 | 02000000 | 04000,
      CREATE = 1 | 0100 | 0200 | 0400000 | 02000000;
  private int fd;

  private NativeDirectory(int fd) {
    this.fd = fd;
  }

  static NativeDirectory open(Path path) throws IOException {
    NativeInput.platform();
    IO.need(
        path.isAbsolute() && path.equals(path.normalize()),
        "Absolute normalized directory required");
    int current = -1;
    try (var arena = Arena.ofConfined()) {
      current = (int) OPEN.invokeExact(arena.allocateFrom("/"), DIRECTORY);
      IO.need(current >= 0, "Cannot open filesystem directory root");
      for (Path component : path) {
        int next =
            (int)
                OPENAT.invokeExact(current, arena.allocateFrom(component.toString()), DIRECTORY, 0);
        IO.need(next >= 0, "Directory contains symlink or non-directory: " + path);
        closeFd(current);
        current = next;
      }
      return new NativeDirectory(current);
    } catch (Throwable error) {
      if (current >= 0)
        try {
          closeFd(current);
        } catch (IOException suppressed) {
          error.addSuppressed(suppressed);
        }
      if (error instanceof IOException io) throw io;
      throw new IOException("Cannot open directory descriptor: " + path, error);
    }
  }

  FileChannel create(String name) throws IOException {
    IO.need(
        !name.isEmpty() && !name.contains("/") && !name.equals(".") && !name.equals(".."),
        "Simple private filename required");
    int created = -1;
    try (var arena = Arena.ofConfined()) {
      created = (int) OPENAT.invokeExact(fd, arena.allocateFrom(name), CREATE, 0600);
      IO.need(created >= 0, "Private output already exists or cannot be created: " + name);
      // This duplicates our already-owned descriptor, never an operator-supplied symlink.
      return FileChannel.open(Path.of("/proc/self/fd/" + created), StandardOpenOption.WRITE);
    } catch (Throwable error) {
      if (error instanceof IOException io) throw io;
      throw new IOException("Private descriptor creation failed: " + name, error);
    } finally {
      if (created >= 0) closeFd(created);
    }
  }

  void force(boolean metadata) throws IOException {
    try {
      int result = (int) FSYNC.invokeExact(fd);
      IO.need(result == 0, "Directory fsync failed");
    } catch (Throwable error) {
      if (error instanceof IOException io) throw io;
      throw new IOException("Directory fsync failed", error);
    }
  }

  private static void closeFd(int fd) throws IOException {
    try {
      int result = (int) CLOSE.invokeExact(fd);
      IO.need(result == 0, "Directory descriptor close failed");
    } catch (Throwable error) {
      if (error instanceof IOException io) throw io;
      throw new IOException("Directory descriptor close failed", error);
    }
  }

  public void close() throws IOException {
    int owned = fd;
    fd = -1;
    if (owned >= 0) closeFd(owned);
  }
}
