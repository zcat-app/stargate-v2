// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
import java.util.zip.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class ReleaseCollectorsTest {
    @TempDir Path root;
    static final Instant NOW = Instant.parse("2026-10-31T12:34:56Z");
    static final String HASH = "a".repeat(64);
    static final String NYM_PIN = "nym-binaries-v2026.1-first";
    static final String NYM_NEW = "nym-binaries-v2026.2-second";
    static final String GHSA = "GHSA-2345-6789-cfgh";
    @Test void sharedJavaPinIsStrictAndKeepsVersion() throws Exception {
        assertEquals("25.0.5", ReleaseCollectors.javaBaseline(bytes("{\"version\":\"25.0.5\"}")));
        for (String value : List.of("{}", "{\"version\":\"other\"}", "{\"version\":\"25.0.5\",\"version\":\"25.0.6\"}", "{\"version\":\"25.0.5\",\"extra\":true}"))
            assertThrows(Exception.class, () -> ReleaseCollectors.javaBaseline(bytes(value)));
    }
    static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    static ReleaseCollectors.Response response(String value) { return new ReleaseCollectors.Response(bytes(value), null); }
    static String releases(String first, String second) { return "[{\"tag_name\":\"" + first + "\",\"draft\":false,\"prerelease\":false,\"published_at\":\"2026-10-01T00:00:00Z\"},{\"tag_name\":\"" + second + "\",\"draft\":false,\"prerelease\":false,\"published_at\":\"2026-10-02T00:00:00Z\"}]"; }
    static String metadata(String versions) { return "<metadata><groupId>io.quarkus.platform</groupId><artifactId>quarkus-bom</artifactId><versioning><lastUpdated>20261030010203</lastUpdated><versions>" + versions + "</versions></versioning></metadata>"; }
    static String stanza(String name, String architecture, String version) { return "Package: " + name + "\nVersion: " + version + "\nArchitecture: " + architecture + "\nFilename: pool/main/t/tor/" + name + "_" + version + "_" + architecture + ".deb\nSHA256: " + HASH + "\n\n"; }
    static String index() { return stanza("tor", "amd64", "0.4.9.9-1") + stanza("tor-geoipdb", "all", "0.4.9.9-1"); }
    static ObjectNode advisory(String repo, String ecosystem) {
        var item = MonitorFiles.object().put("ghsa_id", GHSA).putNull("cve_id").put("state", "published").put("html_url", "https://github.com/" + repo + "/security/advisories/" + GHSA).put("updated_at", "2026-10-01T00:00:00Z");
        var vulnerability = item.putArray("vulnerabilities").addObject().put("vulnerable_version_range", "< 9").put("patched_versions", "9"); vulnerability.putObject("package").put("ecosystem", ecosystem).put("name", "io.netty:netty-codec-http"); return item;
    }
    Path fixture() throws Exception {
        Files.createDirectories(root.resolve("containers")); Files.createDirectories(root.resolve("tools"));
        Files.writeString(root.resolve("containers/nym-release.json"), "{\"tag\":\"" + NYM_PIN + "\"}");
        Files.writeString(root.resolve("containers/i2p-packages.json"), "[{\"version\":\"2.59.0-1noble1\",\"url\":\"https://github.com/PurpleI2P/i2pd/releases/download/2.59.0/i2pd_2.59.0-1noble1_amd64.deb\"}]");
        Files.writeString(root.resolve("containers/java-runtime.json"), "{\"version\":\"25.0.5\"}\n");
        Files.writeString(root.resolve("pom.xml"), "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><properties><quarkus.platform.group-id>io.quarkus.platform</quarkus.platform.group-id><quarkus.platform.artifact-id>quarkus-bom</quarkus.platform.artifact-id><quarkus.platform.version>3.40.1.1</quarkus.platform.version></properties><dependencyManagement><dependencies><dependency><groupId>${quarkus.platform.group-id}</groupId><artifactId>${quarkus.platform.artifact-id}</artifactId><version>${quarkus.platform.version}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>");
        var manifest = MonitorFiles.JSON.createArrayNode(); for (var e : ReleaseCollectors.architectures().entrySet()) manifest.addObject().put("package", e.getKey()).put("version", "0.4.9.9-1").put("url", ReleaseCollectors.TOR_BASE + "pool/main/t/tor/" + e.getKey() + "_0.4.9.9-1_" + e.getValue() + ".deb").put("sha256", HASH);
        Files.write(root.resolve("containers/tor-packages.json"), MonitorFiles.bytes(manifest));
        Path jar = root.resolve("selected.jar"); try (var zip = new ZipOutputStream(Files.newOutputStream(jar))) { zip.putNextEntry(new ZipEntry("META-INF/maven/io.netty/netty-codec-http/pom.properties")); zip.write(bytes("groupId=io.netty\nartifactId=netty-codec-http\nversion=4.2.9.Final\n")); zip.closeEntry(); } return jar;
    }
    ReleaseCollectors.Fetcher successful() {
        return (url, limit) -> {
            if (url.startsWith(ReleaseCollectors.NYM + "?")) return response(releases(NYM_PIN, NYM_NEW));
            if (url.startsWith(ReleaseCollectors.I2PD + "?")) return response(releases("2.59.0", "2.60.0"));
            if (url.equals(ReleaseCollectors.QUARKUS)) return response(metadata("<version>3.40.1.1</version><version>3.40.2</version><version>3.41.0</version>"));
            if (url.equals(ReleaseCollectors.TEMURIN)) return response("[{\"vendor\":\"eclipse\",\"binary\":{\"architecture\":\"x64\",\"os\":\"linux\",\"image_type\":\"jdk\",\"jvm_impl\":\"hotspot\"},\"version\":{\"major\":25,\"openjdk_version\":\"25.0.5+9-LTS\"},\"release_name\":\"jdk-25.0.5+9\"}]");
            if (url.equals(ReleaseCollectors.TOR)) return response(index());
            if (url.equals(ReleaseCollectors.AGE)) return response("{\"tag_name\":\"v1.3.1\",\"draft\":false,\"prerelease\":false,\"html_url\":\"https://github.com/FiloSottile/age/releases/tag/v1.3.1\",\"created_at\":\"2026-10-01T00:00:00Z\",\"published_at\":\"2026-10-02T00:00:00Z\"}");
            if (url.contains("/security-advisories?")) return response("[" + advisory(url.contains("/netty/") ? "netty/netty" : "quarkusio/quarkus", "Maven") + "]");
            throw new AssertionError("unexpected test request");
        };
    }
    @Test void collectsEverySelectedSourceAndPreservesLegacyFields() throws Exception {
        Path jar = fixture(); ObjectNode report = ReleaseCollectors.collect(root, jar, "3.40", "25.0.5+9", "v1.3.0", NOW, successful());
        assertEquals("observed", report.path("outcome").asText(), report.toPrettyString()); var checks = report.path("checks");
        var names = new HashSet<String>(); checks.fieldNames().forEachRemaining(names::add); assertEquals(Set.of("nym", "i2pd", "quarkus", "temurin", "netty", "tor_package_metadata", "age", "advisories", "quarkus_advisories"), names);
        for (JsonNode check : checks) assertEquals("observed", check.path("outcome").asText(), check.toString());
        assertEquals(NYM_NEW, checks.path("nym").path("observation").path("latest_tag").asText());
        assertEquals("3.40.2", checks.path("quarkus").path("observation").path("greatest_numeric_version").asText());
        assertEquals("25.0.5", checks.path("temurin").path("observation").path("source_baseline").path("version").asText());
        assertEquals("4.2.9.Final", checks.path("netty").path("observation").path("modules").get(0).path("version").asText());
        assertEquals("match", checks.path("tor_package_metadata").path("observation").path("packages").path("tor").path("comparison").path("sha256").asText());
        assertEquals("different", checks.path("age").path("observation").path("comparison").asText());
        assertEquals("not_assessed", checks.path("quarkus_advisories").path("observation").path("applicability_status").asText());
        assertEquals("2026-10-31T12:34:56Z", report.path("completed_at").asText());
    }
    @Test void failuresAreIsolatedSanitizedAndSelectedChecksRemainPresent() throws Exception {
        Path jar = fixture(); var normal = successful(); var report = ReleaseCollectors.collect(root, jar, "3.40", null, null, NOW, (url, limit) -> { if (url.startsWith(ReleaseCollectors.NYM)) throw new IOException("secret token remote body"); return normal.get(url, limit); });
        assertEquals("unknown", report.path("outcome").asText()); assertEquals("observed", report.path("checks").path("quarkus").path("outcome").asText()); assertEquals("unknown", report.path("checks").path("age").path("outcome").asText());
        assertEquals("observation failed", report.path("checks").path("nym").path("observation").path("reason").asText()); assertFalse(report.toString().contains("secret"));
    }
    @Test void releasesRequireCompleteUniquePublicationEvidence() throws Exception {
        var full = MonitorFiles.JSON.createArrayNode(); for (int i = 0; i < 10; i++) full.addObject().put("tag_name", "1.0." + i).put("draft", false).put("prerelease", false).put("published_at", "2026-10-01T00:00:00Z");
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.releases(ReleaseCollectors.I2PD, 10, 20, false, (url, limit) -> response(full.toString())));
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.latest(Map.of("one", "2026-10-01T00:00:00Z", "two", "2026-10-01T00:00:00Z"), "one"));
        assertThrows(IOException.class, () -> ReleaseCollectors.releases(ReleaseCollectors.NYM, 100, 10, true, (url, limit) -> response("[{\"tag_name\":\"one\",\"tag_name\":\"two\",\"draft\":false,\"prerelease\":false}]")));
    }
    @Test void paginationRejectsForeignHostsRepositoriesAmbiguityAndQuerySmuggling() throws Exception {
        String valid = "https://api.github.com/repositories/1064563/security-advisories?state=published&per_page=100&after=abc%2Bdef";
        assertEquals(valid, ReleaseCollectors.advisoryNext("<" + valid + ">; rel=\"next\"", "netty/netty"));
        for (String url : List.of(valid.replace("api.github.com", "evil.example"), valid.replace("1064563", "139914932"), valid + "&state=draft", valid.replace("after=abc%2Bdef", "page=2"), valid + "#fragment", valid.replace("api.github.com", "api.github.com:443"))) assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.advisoryNext("<" + url + ">; rel=\"next\"", "netty/netty"));
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.advisoryNext("<" + valid + ">; rel=\"next\",<" + valid + ">; rel=\"next\"", "netty/netty"));
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.releaseNext("<https://api.github.com/repos/nymtech/nym/releases?per_page=100&page=3>; rel=\"next\"", ReleaseCollectors.NYM, 100, 1, true));
        assertFalse(ReleaseCollectors.official("https://evil.example/")); assertTrue(ReleaseCollectors.official(valid));
    }
    @Test void advisoriesPreserveUnknownEcosystemWithoutInferringAndRejectDuplicates() throws Exception {
        var candidate = ReleaseCollectors.advisory(advisory("netty/netty", ""), "netty/netty"); assertEquals("unknown", candidate.path("packages").get(0).path("ecosystem_status").asText());
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.advisory(advisory("quarkusio/quarkus", ""), "quarkusio/quarkus"));
        String duplicates = "[" + advisory("netty/netty", "Maven") + "," + advisory("netty/netty", "Maven") + "]"; assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.advisories("netty/netty", (url, limit) -> response(duplicates)));
        var bad = advisory("netty/netty", "Maven"); bad.put("html_url", "https://evil.example/"); assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.advisory(bad, "netty/netty"));
    }
    @Test void quarkusUsesNumericFamilyOrderingAndRejectsEquivalentOrUnsafeXml() throws Exception {
        var result = ReleaseCollectors.quarkusCompare("3.40.1.1", "3.40", bytes(metadata("<version>3.40.1.1</version><version>3.40.10</version><version>3.40.2</version><version>3.40.99.CR1</version><version>3.41.0</version>")));
        assertEquals("3.40.10", result.path("greatest_numeric_version").asText());
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.quarkusCompare("3.40.1", "3.40", bytes(metadata("<version>3.40.1</version><version>3.40.1.0</version>"))));
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.xml(bytes("<!DOCTYPE metadata [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><metadata>&x;</metadata>")));
    }
    @Test void torRejectsAmbiguityContinuationsAndMissingPackages() throws Exception {
        assertEquals("0.4.9.9-1", ReleaseCollectors.torIndex(bytes(index())).get("tor").path("version").asText());
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.torIndex(bytes(index() + stanza("tor", "amd64", "0.4.9.9-1"))));
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.torIndex(bytes(index().replace("Version: 0.4.9.9-1\n", "Version: 0.4.9.9-1\n continued\n"))));
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.torIndex(bytes(stanza("tor", "amd64", "0.4.9.9-1"))));
        assertFalse(ReleaseCollectors.filename("pool/main/../escape.deb"));
    }
    @Test void nettyReportsUnsupportedPropertiesAndRejectsConflictingCoordinates() throws Exception {
        Path jar = root.resolve("unsupported.jar");
        try (var zip = new ZipOutputStream(Files.newOutputStream(jar))) { zip.putNextEntry(new ZipEntry("META-INF/maven/io.netty/netty-common/pom.properties")); zip.write(bytes("version:4.2.9.Final\n")); zip.closeEntry(); }
        var observation = ReleaseCollectors.netty(jar); assertEquals("unknown", observation.path("metadata_status").asText()); assertEquals(1, observation.path("unsupported_metadata_entries").size());
        try (var zip = new ZipOutputStream(Files.newOutputStream(jar))) { zip.putNextEntry(new ZipEntry("META-INF/maven/io.netty/netty-common/pom.properties")); zip.write(bytes("groupId=evil\nartifactId=netty-common\nversion=4.2.9.Final\n")); zip.closeEntry(); }
        assertThrows(ReleaseCollectors.Invalid.class, () -> ReleaseCollectors.netty(jar));
    }
    @Test void boundedSubscriberCancelsBeforeAccumulatingExcessBytes() throws Exception {
        var body = new ReleaseCollectors.BoundedBody(4); var cancelled = new boolean[1]; body.onSubscribe(new Flow.Subscription() { public void request(long count) {} public void cancel() { cancelled[0] = true; } });
        body.onNext(List.of(ByteBuffer.wrap(new byte[5]))); assertTrue(cancelled[0]); assertThrows(ExecutionException.class, () -> body.getBody().toCompletableFuture().get());
    }
}
