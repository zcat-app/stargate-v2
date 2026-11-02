// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import static org.junit.jupiter.api.Assertions.*;

class RuntimeContextTest {
    @TempDir Path temp;
    private static final String HASH="a".repeat(64), OTHER="b".repeat(64), IMAGE="sha256:"+"c".repeat(64);
    private Path source() throws Exception {
        Path containers=Files.createDirectory(temp.resolve("containers"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path sender=Files.createDirectory(containers.resolve("simplex-alert"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        write(containers.resolve("nym-release.json"),MonitorFiles.object().put("sha256",HASH).put("tag","nym-tag"));
        write(sender.resolve("release.json"),MonitorFiles.object().put("sha256",OTHER).put("version","1.2.3"));return temp;
    }
    private void write(Path path,ObjectNode data) throws Exception { Files.write(path,MonitorFiles.bytes(data));Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------")); }
    private ObjectNode report() {
        var r=MonitorFiles.object().put("security_status","not_assessed");var images=r.putObject("images");var nym=images.putObject("nym").put("image_id",IMAGE);
        nym.putArray("files").addObject().put("image_path","/bin/nym").put("sha256",HASH).putNull("java_release_metadata");
        var app=images.putObject("app").put("image_id",IMAGE);app.putArray("files").addObject().put("image_path","/app/example.jar").put("sha256",OTHER).putNull("java_release_metadata");
        var records=r.putArray("package_records");records.addObject().put("role","app").put("image_id",IMAGE).put("evidence","scanner_package").put("ecosystem","Maven").put("name","io.netty:netty-codec").put("version","1.0");records.addObject().put("role","app").put("image_id",IMAGE).put("evidence","scanner_package").put("ecosystem","Maven").put("name","io.quarkus:core").put("version","3.1");return r;
    }
    private ObjectNode releases() {
        var r=MonitorFiles.object().put("schema_version",1).put("security_status","not_assessed").put("deployment_status","not_assessed").put("completed_at","2026-01-01T00:00:00Z");var checks=r.putObject("checks");
        for(String name:new String[]{"nym","i2pd","quarkus","temurin","netty","tor_package_metadata","age"}) checks.putObject(name).put("outcome","unknown").putObject("observation").put("status","unknown");
        var nym=(ObjectNode)checks.path("nym");nym.put("outcome","observed");nym.putObject("observation").put("pinned_tag","nym-tag").put("status","current");
        var netty=(ObjectNode)checks.path("netty");netty.put("outcome","observed");netty.putObject("observation").put("sha256",OTHER).put("metadata_status","observed");
        var quarkus=(ObjectNode)checks.path("quarkus");quarkus.put("outcome","observed");quarkus.putObject("observation").put("declared_version","3.1").put("status","current");
        var advisory=checks.putObject("advisories").put("outcome","observed").putObject("observation").put("status","observed").put("checked_at","2026-01-01T00:00:00Z");
        var candidate=advisory.putArray("candidates").addObject().put("ghsa_id","GHSA-test").putNull("cve_id");var packages=candidate.putArray("packages");packages.addObject().put("ecosystem","Maven").put("name","io.netty:netty-codec").put("vulnerable_version_range",">= 2");packages.addObject().put("ecosystem","PyPI").put("name","io.netty:netty-codec");
        checks.putObject("quarkus_advisories").put("outcome","unknown").putObject("observation").put("status","unknown").put("checked_at","2026-01-01T00:00:00Z").putNull("candidates");return r;
    }
    @Test void joinsOnlyMatchingSelectedBytesAndCoordinatesWithoutApplicabilityClaims() throws Exception {
        Path root=source();var report=report();var releases=releases();RuntimeContext.enrich(report,releases,root);
        assertEquals("bytes_match",report.path("pin_matches").path("nym").path("comparison").asText());assertEquals("unknown",report.path("pin_matches").path("sender").path("comparison").asText());
        assertEquals("matching_pin",report.path("release").path("checks").path("nym").path("pinned_bytes_comparison").asText());assertEquals(1,report.path("release").path("checks").path("netty").path("selected_files_with_matching_sha256").size());
        assertEquals("all_equal",report.path("release").path("checks").path("quarkus").path("comparison").asText());
        var candidate=report.path("advisories").path("netty").path("candidates").get(0);assertEquals(1,candidate.path("matches").size());assertEquals("not_assessed",candidate.path("applicability").asText());
        assertEquals("unknown",report.path("advisories").path("quarkus").path("status").asText());assertTrue(report.path("advisories").path("quarkus").path("candidates").isNull());assertEquals("not_assessed",report.path("security_status").asText());
    }
    @Test void mismatchedBytesOrPinNeverClaimMatchAndInvalidInputsDoNotMutateReport() throws Exception {
        Path root=source();var report=report();var release=releases();((ObjectNode)report.path("images").path("nym").path("files").get(0)).put("sha256",OTHER);RuntimeContext.enrich(report,release,root);
        assertEquals("unknown",report.path("pin_matches").path("nym").path("comparison").asText());assertEquals("unknown",report.path("release").path("checks").path("nym").path("pinned_bytes_comparison").asText());
        var snapshot=report.deepCopy();((ObjectNode)release.path("checks").path("advisories")).put("outcome","unknown");assertThrows(Exception.class,()->RuntimeContext.enrich(report,release,root));assertEquals(snapshot,report);
    }
}
