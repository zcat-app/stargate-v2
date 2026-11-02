// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** Import only an idle, fully acknowledged legacy ledger. Never changes its database. */
final class LegacyImport {
    static final Set<String> OLD_SCHEMA=Set.of(
        "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), epoch TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0), last_now TEXT NOT NULL, max_age INTEGER NOT NULL CHECK(max_age>0))",
        "CREATE TABLE checks (name TEXT PRIMARY KEY, health TEXT NOT NULL CHECK(health IN ('observed','unknown')), watermark TEXT, evidence TEXT, baseline TEXT)",
        "CREATE TABLE advisories (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, updated TEXT NOT NULL)",
        "CREATE TABLE pending (id INTEGER PRIMARY KEY CHECK(id=1), event_id TEXT NOT NULL, payload TEXT NOT NULL)"
    );
    static final String QUARKUS_SCHEMA="CREATE TABLE quarkus_advisories (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, updated TEXT NOT NULL)";
    static ObjectNode read(Path ledger, Path bridge, Path dispatch) throws Exception {
        try(var ledgerLock=new LegacyLock(ledger.resolve("change.lock"),false);var bridgeLock=new LegacyLock(bridge,true);var dispatchLock=new LegacyLock(dispatch,true)) {return readLocked(ledger,bridge,dispatch);}
    }
    private static ObjectNode readLocked(Path ledger, Path bridge, Path dispatch) throws Exception {
        MonitorFiles.directory(ledger,true);MonitorFiles.directory(bridge,true);MonitorFiles.directory(dispatch,true);
        Path database=ledger.resolve("changes.sqlite3");
        for(String suffix:List.of("-journal","-wal","-shm")) {
            Path sidecar=Path.of(database+suffix);
            if(Files.exists(sidecar,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("legacy journal present; stop all writers and investigate");
        }
        Path transaction=bridge.resolve("state.json");
        if(Files.exists(transaction,LinkOption.NOFOLLOW_LINKS)) {
            var value=MonitorFiles.json(transaction,1024,true);
            String id=value.path("event_id").asText();
            if(value.size()!=5||value.path("schema_version").asInt()!=1||!MonitorLedger.hash(value.path("text_sha256"))||value.path("receipt").size()!=2||!value.path("receipt").path("exit_code").isIntegralNumber()||!value.path("phase").asText().equals("acknowledged")||!id.matches("[0-9a-f]{32}-[1-9][0-9]{0,18}")
                    ||!value.path("receipt").path("stdout").asText().equals("ACCEPTED\n")||value.path("receipt").path("exit_code").asInt(-1)!=0)
                throw new IllegalArgumentException("legacy alert is unresolved; no import performed");
            var receipt=MonitorFiles.read(dispatch.resolve("event-"+id+".result"),64,true);
            if(!Arrays.equals(receipt,"ACCEPTED\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))throw new IllegalArgumentException("legacy dispatch receipt mismatch");
            if(!Arrays.equals(MonitorFiles.read(dispatch.resolve("event-"+id+".attempt"),64,true),"UNKNOWN\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))throw new IllegalArgumentException("legacy dispatch attempt mismatch");
        }
        byte[] before=MonitorFiles.read(database,MonitorFiles.REPORT_LIMIT,true);
        var output=MonitorFiles.object();output.put("schema_version",1);
        try(var db=new LegacySqlite(database)) {
            var schema=db.query("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL",1);var actual=schema.stream().map(List::getFirst).collect(java.util.stream.Collectors.toSet());var current=new HashSet<>(OLD_SCHEMA);current.add(QUARKUS_SCHEMA);
            if(schema.size()!=actual.size()||(!actual.equals(OLD_SCHEMA)&&!actual.equals(current)))throw new IllegalArgumentException("legacy schema differs");
            if(!db.query("PRAGMA quick_check",1).equals(List.of(List.of("ok")))
                    ||!db.query("PRAGMA journal_mode",1).equals(List.of(List.of("delete"))))throw new IllegalArgumentException("legacy database integrity or journal mode unknown");
            if(!db.query("SELECT event_id FROM pending",1).isEmpty())throw new IllegalArgumentException("legacy pending alert must be resolved before migration");
            var rows=db.query("SELECT epoch,sequence,last_now,max_age FROM meta",4);
            if(rows.size()!=1)throw new IllegalArgumentException("legacy metadata missing");
            var meta=rows.getFirst();
            if(!meta.get(0).matches("[0-9a-f]{32}"))throw new IllegalArgumentException("legacy event identity invalid");
            long sequence=Long.parseLong(meta.get(1)),age=Long.parseLong(meta.get(3));
            if(sequence<0||age<=0||Instant.parse(meta.get(2)).isAfter(Instant.now()))throw new IllegalArgumentException("legacy clock/policy invalid");
            output.put("epoch",meta.get(0));output.put("sequence",sequence);output.put("last_now",meta.get(2));output.put("max_age_seconds",age);
            var checks=output.putObject("checks");
            for(var row:db.query("SELECT name,health,watermark,evidence,baseline FROM checks ORDER BY name",5)) {
                String name=row.get(0);if(!MonitorLedger.NAMES.contains(name)||checks.has(name)||!Set.of("observed","unknown").contains(row.get(1)))throw new IllegalArgumentException("legacy check invalid");
                var check=checks.putObject(name);check.put("health",row.get(1));check.put("watermark",row.get(2));check.put("evidence",row.get(3));check.put("baseline",row.get(4));
            }
            for(String table:List.of("advisories","quarkus_advisories")) {
                var entries=output.putObject(table);
                if(table.equals("quarkus_advisories")&&actual.equals(OLD_SCHEMA))continue;
                for(var row:db.query("SELECT id,fingerprint,updated FROM "+table+" ORDER BY id",3)) {
                    if(!row.get(0).matches("GHSA-[a-z0-9-]+")||!row.get(1).matches("[0-9a-f]{64}"))throw new IllegalArgumentException("legacy advisory invalid");
                    Instant.parse(row.get(2));var entry=entries.putObject(row.get(0));entry.put("fingerprint",row.get(1));entry.put("updated",row.get(2));
                }
            }
        }
        if(!Arrays.equals(before,MonitorFiles.read(database,MonitorFiles.REPORT_LIMIT,true)))throw new IllegalArgumentException("legacy writer changed during import");
        output.putNull("pending");output.put("legacy_database_sha256",MonitorFiles.hash(before));return output;
    }
}
