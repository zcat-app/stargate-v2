// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static java.lang.foreign.ValueLayout.*;
import static org.junit.jupiter.api.Assertions.*;

class LegacyImportTest {
    private static final String EPOCH = "0123456789abcdef0123456789abcdef";
    private static final String TIME = "2026-01-01T00:00:00Z";
    private static final String BASELINE = "a".repeat(64);
    private static final String[] OLD_SCHEMA = {
        "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), epoch TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0), last_now TEXT NOT NULL, max_age INTEGER NOT NULL CHECK(max_age>0))",
        "CREATE TABLE checks (name TEXT PRIMARY KEY, health TEXT NOT NULL CHECK(health IN ('observed','unknown')), watermark TEXT, evidence TEXT, baseline TEXT)",
        "CREATE TABLE advisories (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, updated TEXT NOT NULL)",
        "CREATE TABLE pending (id INTEGER PRIMARY KEY CHECK(id=1), event_id TEXT NOT NULL, payload TEXT NOT NULL)"
    };
    private static final String QUARKUS = "CREATE TABLE quarkus_advisories (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, updated TEXT NOT NULL)";
    @TempDir Path temp;

    // Real SQLite fixture: use only the OS library, never a shell, Python or sqlite CLI.
    private static void sql(Path file, String... statements) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            var library = SymbolLookup.libraryLookup("libsqlite3.so.0", arena);
            var linker = Linker.nativeLinker();
            MethodHandle open = linker.downcallHandle(library.find("sqlite3_open_v2").orElseThrow(), FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS));
            MethodHandle exec = linker.downcallHandle(library.find("sqlite3_exec").orElseThrow(), FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
            MethodHandle close = linker.downcallHandle(library.find("sqlite3_close").orElseThrow(), FunctionDescriptor.of(JAVA_INT, ADDRESS));
            var ptr = arena.allocate(ADDRESS);
            assertEquals(0, (int)open.invokeExact(arena.allocateFrom(file.toString()), ptr, 2, MemorySegment.NULL));
            var db = ptr.get(ADDRESS, 0);
            try {
                for (String statement : statements) {
                    int code = (int)exec.invokeExact(db, arena.allocateFrom(statement), MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL);
                    assertEquals(0, code, "fixture SQL failed: " + statement);
                }
            } finally { assertEquals(0, (int)close.invokeExact(db)); }
        }
    }
    private Path privateDir(String name) throws Exception {
        return Files.createDirectory(temp.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    private static void privateWrite(Path path, byte[] bytes) throws Exception {
        Files.write(path,bytes); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
    private record Fixture(Path ledger, Path bridge, Path dispatch, Path db, byte[] before) {}
    private Fixture fixture(boolean oldSchema, boolean pending) throws Throwable {
        Path ledger=privateDir("ledger"), bridge=privateDir("bridge"), dispatch=privateDir("dispatch"), db=ledger.resolve("changes.sqlite3");
        Files.createFile(db, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        var statements = new ArrayList<>(List.of(OLD_SCHEMA));
        if (!oldSchema) statements.add(QUARKUS);
        statements.add("INSERT INTO meta VALUES(1,'"+EPOCH+"',7,'"+TIME+"',3600)");
        statements.add("INSERT INTO checks VALUES('nym','observed','"+TIME+"','"+MonitorLedger.proof(BASELINE)+"','"+BASELINE+"')");
        statements.add("INSERT INTO checks VALUES('netty','unknown',NULL,NULL,NULL)");
        if (pending) statements.add("INSERT INTO pending VALUES(1,'"+EPOCH+"-7','{}')");
        sql(db, statements.toArray(String[]::new));
        return new Fixture(ledger,bridge,dispatch,db,Files.readAllBytes(db));
    }
    private void assertUnchanged(Fixture f) throws Exception {
        assertArrayEquals(f.before, Files.readAllBytes(f.db));
        for (String suffix : List.of("-journal","-wal","-shm")) assertFalse(Files.exists(Path.of(f.db+suffix)));
    }
    @Test void importsIdleAcknowledgedLedgerAndLeavesDatabaseUnchanged() throws Throwable {
        Fixture f=fixture(false,false); String id=EPOCH+"-7";
        var bridge=MonitorFiles.object().put("schema_version",1).put("event_id",id).put("text_sha256","b".repeat(64)).put("phase","acknowledged");
        bridge.putObject("receipt").put("stdout","ACCEPTED\n").put("exit_code",0);
        privateWrite(f.bridge.resolve("state.json"),MonitorFiles.bytes(bridge));
        privateWrite(f.dispatch.resolve("event-"+id+".result"),"ACCEPTED\n".getBytes(StandardCharsets.US_ASCII));
        privateWrite(f.dispatch.resolve("event-"+id+".attempt"),"UNKNOWN\n".getBytes(StandardCharsets.US_ASCII));
        var state=LegacyImport.read(f.ledger,f.bridge,f.dispatch);
        assertEquals(EPOCH,state.path("epoch").asText()); assertEquals(7,state.path("sequence").asLong());
        assertEquals(TIME,state.path("last_now").asText()); assertEquals(3600,state.path("max_age_seconds").asLong());
        assertEquals("observed",state.path("checks").path("nym").path("health").asText());
        assertEquals(BASELINE,state.path("checks").path("nym").path("baseline").asText());
        assertEquals(MonitorLedger.proof(BASELINE),state.path("checks").path("nym").path("evidence").asText());
        assertEquals(TIME,state.path("checks").path("nym").path("watermark").asText());
        assertTrue(state.path("checks").path("netty").path("baseline").isNull());
        assertTrue(state.path("pending").isNull()); MonitorLedger.validate(state); assertUnchanged(f);
    }
    @Test void refusesPendingLedger() throws Throwable {
        Fixture f=fixture(false,true);
        assertThrows(Exception.class,()->LegacyImport.read(f.ledger,f.bridge,f.dispatch)); assertUnchanged(f);
    }
    @Test void refusesUnresolvedBridgeAndWrongReceipt() throws Throwable {
        Fixture f=fixture(false,false); String id=EPOCH+"-7";
        var bridge=MonitorFiles.object().put("schema_version",1).put("event_id",id).put("text_sha256","b".repeat(64)).put("phase","accepted");
        bridge.putObject("receipt").put("stdout","ACCEPTED\n").put("exit_code",0);
        privateWrite(f.bridge.resolve("state.json"),MonitorFiles.bytes(bridge));
        assertThrows(Exception.class,()->LegacyImport.read(f.ledger,f.bridge,f.dispatch)); assertUnchanged(f);
        bridge.put("phase","acknowledged"); privateWrite(f.bridge.resolve("state.json"),MonitorFiles.bytes(bridge));
        privateWrite(f.dispatch.resolve("event-"+id+".result"),"different\n".getBytes(StandardCharsets.US_ASCII));
        assertThrows(Exception.class,()->LegacyImport.read(f.ledger,f.bridge,f.dispatch)); assertUnchanged(f);
    }
    @Test void refusesUnknownDatabaseSchema() throws Throwable {
        Fixture initial=fixture(false,false); sql(initial.db,"CREATE TABLE unexpected (value TEXT)"); Fixture f=new Fixture(initial.ledger,initial.bridge,initial.dispatch,initial.db,Files.readAllBytes(initial.db));
        assertThrows(Exception.class,()->LegacyImport.read(f.ledger,f.bridge,f.dispatch)); assertUnchanged(f);
    }
    @Test void refusesMalformedAcknowledgedBridge() throws Throwable {
        Fixture f=fixture(false,false); String id=EPOCH+"-7"; var bridge=MonitorFiles.object().put("event_id",id).put("phase","acknowledged"); bridge.putObject("receipt").put("stdout","ACCEPTED\n").put("exit_code",0);
        privateWrite(f.bridge.resolve("state.json"),MonitorFiles.bytes(bridge)); privateWrite(f.dispatch.resolve("event-"+id+".result"),"ACCEPTED\n".getBytes(StandardCharsets.US_ASCII));
        assertThrows(Exception.class,()->LegacyImport.read(f.ledger,f.bridge,f.dispatch)); assertUnchanged(f);
    }
    @Test void importsExactOldSchemaWithoutMutatingOrUpgradingDatabase() throws Throwable {
        Fixture f=fixture(true,false);
        var state=LegacyImport.read(f.ledger,f.bridge,f.dispatch);
        assertEquals(EPOCH,state.path("epoch").asText()); assertEquals(7,state.path("sequence").asLong());
        assertEquals(BASELINE,state.path("checks").path("nym").path("baseline").asText());
        assertTrue(state.path("quarkus_advisories").isEmpty()); MonitorLedger.validate(state); assertUnchanged(f);
    }
}
