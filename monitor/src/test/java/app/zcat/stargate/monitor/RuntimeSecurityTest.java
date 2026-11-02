// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

class RuntimeSecurityTest {
    @Test void trivyRepositoryArtifactIdIsRetainedWhileImageIdMustMatch() throws Exception {
        var raw=scan(ID).put("ArtifactID",OTHER);((ObjectNode)raw.path("Trivy")).put("Version","0.76.1");Path scan=write("scan.json",raw),sel=write("selection.json",selection(scan)),map=write("containers.json",mapping()),state=recorder();
        RuntimeSecurity.Query query=q->{var result=MonitorFiles.object();result.putArray("results").addObject();return result;};
        var report=RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(ID),query);assertEquals(OTHER,report.path("images").path("app").path("scan").path("source_binding").path("artifact_id").asText());assertEquals(ID,report.path("images").path("app").path("scan").path("source_binding").path("metadata_image_id").asText());
        ((ObjectNode)raw.path("Metadata")).put("ImageID",OTHER);write("scan.json",raw);assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(ID),query));
    }
    @Test void slowResponseBodyHasWholeRequestDeadline() throws Exception {
        var release=new java.util.concurrent.CountDownLatch(1);
        try(var listener=new java.net.ServerSocket(0,1,java.net.InetAddress.getLoopbackAddress())) {
            var server=Thread.startVirtualThread(()->{try(var socket=listener.accept()) {var reader=new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream()));String line;while((line=reader.readLine())!=null&&!line.isEmpty()){}socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{".getBytes(java.nio.charset.StandardCharsets.US_ASCII));socket.getOutputStream().flush();release.await();}catch(Exception ignored){}});
            try {assertTimeoutPreemptively(java.time.Duration.ofSeconds(3),()->assertThrows(Exception.class,()->RuntimeSecurity.post(java.net.URI.create("http://127.0.0.1:"+listener.getLocalPort()+"/"),MonitorFiles.JSON.createArrayNode(),java.time.Duration.ofMillis(250))));}
            finally {release.countDown();server.join(1000);}
        }
    }
    @TempDir Path temp;
    static final String ID="sha256:"+"a".repeat(64), OTHER="sha256:"+"b".repeat(64), CID="c".repeat(64);
    Path write(String name, ObjectNode json) throws Exception { Path p=temp.resolve(name); Files.write(p,MonitorFiles.bytes(json)); Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rw-------")); return p; }
    Path recorder() throws Exception { Path p=Files.createDirectory(temp.resolve("state")); Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rwx------")); return p; }
    ObjectNode selection(Path scan) { var n=MonitorFiles.object().put("schema_version",1); var i=n.putArray("images").addObject().put("role","app").put("image_id",ID).put("scan",scan.toString()); i.putArray("files"); return n; }
    ObjectNode mapping() { var n=MonitorFiles.object().put("schema_version",1); n.putObject("containers").put("app","my-app"); return n; }
    ObjectNode scan(String id) { var n=MonitorFiles.object().put("SchemaVersion",2).put("ArtifactType","container_image").put("ArtifactID",id).put("CreatedAt","2026-01-01T00:00:00Z"); n.putObject("Metadata").put("ImageID",id); n.putObject("Trivy").put("Version","0.70.0"); var target=n.putArray("Results").addObject().put("Target","app.jar").put("Class","lang-pkgs").put("Type","jar"); target.putArray("Packages").addObject().put("Name","org.example:thing").put("Version","1.2.3"); target.putArray("Vulnerabilities").addObject().put("VulnerabilityID","CVE-2026-1").put("PkgName","org.example:thing").put("InstalledVersion","1.2.3").put("Severity","HIGH"); return n; }
    String docker(String id) { return "/my-app "+CID+" "+id+" true\n"; }
    @Test void observesSelectedImageAndExactCoordinates() throws Exception {
        Path scan=write("scan.json",scan(ID)), sel=write("selection.json",selection(scan)), map=write("containers.json",mapping()), state=recorder();
        var result=RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,names->{assertEquals(List.of("my-app"),names);return docker(ID);},queries->{assertEquals("org.example:thing",queries.get(0).path("package").path("name").asText()); var n=MonitorFiles.object(); n.putArray("results").addObject().putArray("vulns").addObject().put("id","CVE-2026-2").put("modified","2026-01-01T00:00:00Z"); return n;});
        assertEquals("observed",result.path("deployment_binding").path("status").asText()); assertEquals("CVE-2026-2",result.path("osv_observation").path("queries").get(0).path("candidates").get(0).path("id").asText()); assertEquals("retained_unassessed",result.path("dispositions").get(0).path("status").asText()); assertEquals(result,MonitorFiles.json(state.resolve("latest-security-binding.json"),MonitorFiles.REPORT_LIMIT,true));
    }
    @Test void mismatchAndIncompleteOsvInvalidateOldReport() throws Exception {
        Path scan=write("scan.json",scan(ID)), sel=write("selection.json",selection(scan)), map=write("containers.json",mapping()), state=recorder();
        assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(OTHER),q->MonitorFiles.object()));
        assertEquals("unknown",MonitorFiles.json(state.resolve("latest-security-binding.json"),1024,true).path("status").asText());
        Files.write(scan,MonitorFiles.bytes(scan(OTHER))); assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(ID),q->MonitorFiles.object()));
        Files.write(scan,MonitorFiles.bytes(scan(ID))); assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(ID),q->{var r=MonitorFiles.object();r.putArray("results");return r;}));
        assertEquals("unknown",MonitorFiles.json(state.resolve("latest-security-binding.json"),1024,true).path("status").asText());
    }
    @Test void jarCoordinatesAndOperatorDispositionAreBound() throws Exception {
        Path jar=temp.resolve("library.jar"); try(var out=new ZipOutputStream(Files.newOutputStream(jar))) { out.putNextEntry(new ZipEntry("META-INF/maven/org.example/library/pom.properties")); out.write("groupId=org.example\nartifactId=library\nversion=4.2\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII)); out.closeEntry(); } Files.setPosixFilePermissions(jar,PosixFilePermissions.fromString("rw-------"));
        var scanned=scan(ID); Path scan=write("scan.json",scanned); var selected=selection(scan); ((ArrayNode)selected.path("images").get(0).path("files")).addObject().put("image_path","/app/library.jar").put("local_path",jar.toString()); Path sel=write("selection.json",selected), map=write("containers.json",mapping()), state=recorder();
        Path evidence=temp.resolve("evidence.txt"); Files.writeString(evidence,"reviewed"); Files.setPosixFilePermissions(evidence,PosixFilePermissions.fromString("rw-------")); var supplied=MonitorFiles.object().put("schema_version",1); var d=supplied.putArray("dispositions").addObject().put("role","app").put("image_id",ID).put("scan_sha256",MonitorFiles.hash(Files.readAllBytes(scan))).put("target_index",0).put("id","CVE-2026-1").put("package","org.example:thing").put("installed_version","1.2.3").put("status","backport_evidence").put("note","operator reviewed"); d.putArray("evidence_files").add(evidence.toString()); Path dispositions=write("dispositions.json",supplied);
        var result=RuntimeSecurity.collect(sel,map,dispositions,300,Instant.now(),state,n->docker(ID),queries->{ var r=MonitorFiles.object(); var a=r.putArray("results"); queries.forEach(q->a.addObject()); return r; });
        assertEquals("org.example:library",result.path("images").path("app").path("files").get(0).path("coordinates").get(0).path("name").asText()); assertEquals("backport_evidence",result.path("dispositions").get(0).path("status").asText()); assertEquals(2,result.path("osv_observation").path("queries").size());
        Files.writeString(jar,"invalid archive"); assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,dispositions,300,Instant.now(),state,n->docker(ID),q->MonitorFiles.object()));
    }
    @Test void nymSourceGraphRequiresBoundBinaryAndBuildMetadata() throws Exception {
        Path binary=temp.resolve("nym.bin"); Files.writeString(binary,"nym executable"); Files.setPosixFilePermissions(binary,PosixFilePermissions.fromString("rw-------")); String commit="d".repeat(40), lock="e".repeat(64); var build=MonitorFiles.object().put("binarySha256",MonitorFiles.hash(Files.readAllBytes(binary))).put("sourceCommit",commit).put("cargoLockSha256",lock); Path buildPath=write("build.json",build); var graph=MonitorFiles.object().put("sourceCommit",commit).put("cargoLockSha256",lock).put("selectedGraphSha256","f".repeat(64)); graph.putArray("packages").addObject().put("source","registry+https://github.com/rust-lang/crates.io-index").put("name","test-crate").put("version","1.0.0"); Path graphPath=write("graph.json",graph), scan=write("scan.json",scan(ID)); var selected=selection(scan); var image=(ObjectNode)selected.path("images").get(0); image.put("role","nym"); ((ArrayNode)image.path("files")).addObject().put("image_path","/bin/nym").put("local_path",binary.toString()); ((ArrayNode)image.path("files")).addObject().put("image_path","/bin/build.json").put("local_path",buildPath.toString()); selected.putArray("source_graphs").addObject().put("role","nym").put("binary_image_path","/bin/nym").put("build_metadata_image_path","/bin/build.json").put("graph_path",graphPath.toString()); Path sel=write("selection.json",selected); var mapping=MonitorFiles.object().put("schema_version",1); mapping.putObject("containers").put("nym","my-app"); Path map=write("containers.json",mapping), state=recorder();
        var result=RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(ID),queries->{ var response=MonitorFiles.object(); var a=response.putArray("results"); queries.forEach(q->a.addObject()); return response; }); assertTrue(result.path("osv_observation").path("queries").toString().contains("test-crate"));
        Files.writeString(binary,"changed binary"); assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(ID),q->MonitorFiles.object()));
    }
    @Test void rejectsPaginatedOsvResults() throws Exception {
        Path scan=write("scan.json",scan(ID)), sel=write("selection.json",selection(scan)), map=write("containers.json",mapping()), state=recorder(); assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,null,300,Instant.now(),state,n->docker(ID),q->{var r=MonitorFiles.object();r.putArray("results").addObject().put("next_page_token","incomplete");return r;}));
    }
    @Test void rejectsStaleIdentityAfterQuery() throws Exception {
        Path scan=write("scan.json",scan(ID)), sel=write("selection.json",selection(scan)), map=write("containers.json",mapping()), state=recorder();
        assertThrows(Exception.class,()->RuntimeSecurity.collect(sel,map,null,1,Instant.now(),state,n->docker(ID),q->{Thread.sleep(1100);var r=MonitorFiles.object();r.putArray("results").addObject();return r;}));
        assertEquals("unknown",MonitorFiles.json(state.resolve("latest-security-binding.json"),1024,true).path("status").asText());
    }
}
