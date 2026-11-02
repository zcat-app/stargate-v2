// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

final class StageNative {
    private StageNative() {}
    static void renameNoReplace(int from, String source, int to, String destination) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            var linker = Linker.nativeLinker();
            var call = linker.downcallHandle(linker.defaultLookup().find("renameat2").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
            if ((int) call.invokeExact(from, arena.allocateFrom(source), to, arena.allocateFrom(destination), 1) != 0) throw new IOException("No-replace publication failed");
        } catch (IOException e) { throw e; } catch (Throwable e) { throw new IOException("Native operation failed", e); }
    }
    static void setTimes(int fd, long seconds) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment times = arena.allocate(32, 8); times.set(ValueLayout.JAVA_LONG, 0, seconds); times.set(ValueLayout.JAVA_LONG, 16, seconds);
            var linker = Linker.nativeLinker();
            var call = linker.downcallHandle(linker.defaultLookup().find("futimens").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            if ((int) call.invokeExact(fd, times) != 0) throw new IOException("Cannot set times");
        } catch (IOException e) { throw e; } catch (Throwable e) { throw new IOException("Native operation failed", e); }
    }
}
