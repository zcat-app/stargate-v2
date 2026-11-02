// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

final class VolumeImportNative {
    private VolumeImportNative() {}
    /** Preserve atime, set mtime to the source's whole second. */
    static void setMtime(int fd, long seconds) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment times = arena.allocate(32, 8);
            times.set(ValueLayout.JAVA_LONG, 8, 1073741822L); // UTIME_OMIT
            times.set(ValueLayout.JAVA_LONG, 16, seconds);
            var linker = Linker.nativeLinker();
            var method = linker.downcallHandle(linker.defaultLookup().find("futimens").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            if ((int) method.invokeExact(fd, times) != 0) throw new IOException("Cannot set mtime");
        } catch (IOException e) { throw e; }
        catch (Throwable e) { throw new IOException("Native operation failed", e); }
    }
}
