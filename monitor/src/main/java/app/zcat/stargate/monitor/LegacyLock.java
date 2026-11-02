// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import java.lang.foreign.*;
import java.nio.file.*;
import static java.lang.foreign.ValueLayout.*;

/** Linux flock compatibility is needed only for the one-time legacy import. */
final class LegacyLock implements AutoCloseable {
    final Arena arena=Arena.ofConfined();
    final SymbolLookup libc=SymbolLookup.libraryLookup("libc.so.6",arena);
    int fd=-1;
    int invoke(String name,FunctionDescriptor type,Object... args) throws Exception {
        try{return (int)Linker.nativeLinker().downcallHandle(libc.find(name).orElseThrow(),type).invokeWithArguments(args);}catch(Throwable e){throw new Exception("legacy lock unavailable",e);}
    }
    LegacyLock(Path path,boolean directory) throws Exception {
        try {
            if(directory)MonitorFiles.directory(path,true);
            else {if(!Files.exists(path,LinkOption.NOFOLLOW_LINKS))MonitorFiles.create(path,new byte[0]);MonitorFiles.read(path,64,true);}
            fd=invoke("open",FunctionDescriptor.of(JAVA_INT,ADDRESS,JAVA_INT),arena.allocateFrom(path.toString()),(directory?0x10000:2)|0x20000|0x80000);
            if(fd<0||invoke("flock",FunctionDescriptor.of(JAVA_INT,JAVA_INT,JAVA_INT),fd,2|4)!=0)throw new IllegalStateException("legacy writer active; import refused");
        }catch(Exception e){close();throw e;}
    }
    public void close() throws Exception {try{if(fd>=0){int old=fd;fd=-1;if(invoke("close",FunctionDescriptor.of(JAVA_INT,JAVA_INT),old)!=0)throw new IllegalStateException("legacy lock close failed");}}finally{arena.close();}}
}
