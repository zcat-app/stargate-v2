// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static java.lang.foreign.ValueLayout.*;

/** One-time read-only import through the host SQLite already used by the old monitor.
 * No JDBC/native artifact is downloaded or bundled. Daily Java monitoring does not use it. */
final class LegacySqlite implements AutoCloseable {
    final Arena arena=Arena.ofConfined();
    final SymbolLookup library=SymbolLookup.libraryLookup("libsqlite3.so.0",arena);
    final Linker linker=Linker.nativeLinker();
    final MemorySegment database;
    MethodHandle function(String name, FunctionDescriptor type) {return linker.downcallHandle(library.find(name).orElseThrow(),type);}
    Object call(String name,FunctionDescriptor type,Object... args) throws Exception {
        try {return function(name,type).invokeWithArguments(args);}catch(Throwable e){throw new Exception("legacy SQLite operation failed",e);}
    }
    LegacySqlite(Path path) throws Exception {
        MonitorFiles.read(path,MonitorFiles.REPORT_LIMIT,true);
        var result=arena.allocate(ADDRESS);
        int code=(int)call("sqlite3_open_v2",FunctionDescriptor.of(JAVA_INT,ADDRESS,ADDRESS,JAVA_INT,ADDRESS),arena.allocateFrom(path.toString()),result,1|0x01000000,MemorySegment.NULL);
        database=result.get(ADDRESS,0);
        if(code!=0){close();throw new IllegalArgumentException("legacy database refused");}
        query("PRAGMA trusted_schema=OFF",0);query("PRAGMA query_only=ON",0);
    }
    List<List<String>> query(String sql,int columns) throws Exception {
        var result=arena.allocate(ADDRESS);
        int code=(int)call("sqlite3_prepare_v2",FunctionDescriptor.of(JAVA_INT,ADDRESS,ADDRESS,JAVA_INT,ADDRESS,ADDRESS),database,arena.allocateFrom(sql),-1,result,MemorySegment.NULL);
        if(code!=0)throw new IllegalArgumentException("legacy schema refused");
        var statement=result.get(ADDRESS,0);var rows=new ArrayList<List<String>>();long total=0;
        try {
            while((code=(int)call("sqlite3_step",FunctionDescriptor.of(JAVA_INT,ADDRESS),statement))==100) {
                var row=new ArrayList<String>();
                for(int i=0;i<columns;i++) {
                    var text=(MemorySegment)call("sqlite3_column_text",FunctionDescriptor.of(ADDRESS,ADDRESS,JAVA_INT),statement,i);
                    int size=(int)call("sqlite3_column_bytes",FunctionDescriptor.of(JAVA_INT,ADDRESS,JAVA_INT),statement,i);
                    total+=size;if(size<0||total>MonitorFiles.REPORT_LIMIT)throw new IllegalArgumentException("legacy report contract exceeded");
                    row.add(text.equals(MemorySegment.NULL)?null:StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(text.reinterpret(size).toArray(JAVA_BYTE))).toString());
                }
                rows.add(row);
            }
            if(code!=101)throw new IllegalArgumentException("legacy read incomplete");
            return rows;
        } finally {call("sqlite3_finalize",FunctionDescriptor.of(JAVA_INT,ADDRESS),statement);}
    }
    @Override public void close() {
        try{if(database!=null&&!database.equals(MemorySegment.NULL))call("sqlite3_close",FunctionDescriptor.of(JAVA_INT,ADDRESS),database);}catch(Exception e){throw new IllegalStateException("legacy read close failed",e);}finally{arena.close();}
    }
}
