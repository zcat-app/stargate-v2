// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

/** Add source and advisory context without claiming vulnerability applicability. */
final class RuntimeContext {
    private static final List<String> RELEASES = List.of("nym", "i2pd", "quarkus", "temurin", "netty", "tor_package_metadata", "age");
    private static void require(boolean condition, String message) throws IOException { if (!condition) throw new IOException(message); }
    private static JsonNode object(JsonNode value) throws IOException { require(value != null && value.isObject(), "expected object"); return value; }
    private static JsonNode array(JsonNode value) throws IOException { require(value != null && value.isArray(), "expected array"); return value; }
    private static String text(JsonNode value) throws IOException { require(value != null && value.isTextual() && !value.textValue().isBlank(), "expected text"); return value.textValue(); }
    private static JsonNode required(JsonNode value, String field) throws IOException { JsonNode result = value.get(field); require(result != null, "missing field " + field); return result; }
    private static String fingerprint(JsonNode value) throws IOException { return MonitorFiles.hash(MonitorFiles.bytes(value)); }
    private static JsonNode read(Path path, ObjectNode result, String role) throws IOException {
        byte[] raw = ReleaseCollectors.read(path.toAbsolutePath().normalize(), 32 * 1024 * 1024);
        JsonNode manifest = object(MonitorFiles.JSON.readTree(raw));
        var pin = result.putObject(role).put("manifest_sha256", MonitorFiles.hash(raw));
        pin.set("pinned_tag", manifest.has("tag") ? manifest.get("tag").deepCopy() : NullNode.instance);
        pin.set("pinned_version", manifest.has("version") ? manifest.get("version").deepCopy() : NullNode.instance);
        return manifest;
    }
    private static boolean observed(String name, JsonNode o) {
        return switch(name) {
            case "nym" -> Set.of("current","newer_release").contains(o.path("status").asText()) && o.path("pinned_tag").isTextual();
            case "i2pd" -> Set.of("current","newer_release").contains(o.path("status").asText()) && o.path("noble_package_version").isTextual();
            case "quarkus" -> Set.of("current","newer_release").contains(o.path("status").asText()) && o.path("declared_version").isTextual();
            case "netty" -> "observed".equals(o.path("metadata_status").asText()) && o.path("sha256").asText().matches("[0-9a-f]{64}");
            case "temurin" -> o.path("source_baseline").path("version").isTextual() && "observed".equals(o.path("upstream").path("status").asText());
            case "tor_package_metadata" -> "observed".equals(o.path("status").asText()) && o.path("packages").isObject();
            case "age" -> "observed".equals(o.path("status").asText());
            default -> false;
        };
    }
    static void enrich(ObjectNode report, JsonNode releaseReport, Path sourceRoot) throws Exception {
        JsonNode images = object(required(report, "images")), records = array(required(report, "package_records"));
        object(releaseReport); JsonNode checks = object(required(releaseReport,"checks"));
        require(releaseReport.path("schema_version").isIntegralNumber() && releaseReport.path("schema_version").intValue() == 1 && "not_assessed".equals(releaseReport.path("security_status").asText()) && "not_assessed".equals(releaseReport.path("deployment_status").asText()), "invalid release report");
        text(required(releaseReport,"completed_at"));
        var pins=MonitorFiles.object();
        for (var choice : Map.of("nym", "containers/nym-release.json", "sender", "containers/simplex-alert/release.json").entrySet()) {
            String role=choice.getKey(); JsonNode manifest=read(sourceRoot.resolve(choice.getValue()),pins,role); var pin=(ObjectNode)pins.get(role); var matches=pin.putArray("matching_files");
            JsonNode selected=images.path(role); if (!selected.isMissingNode()) for(JsonNode f:array(required(selected,"files"))) if(manifest.hasNonNull("sha256") && manifest.get("sha256").equals(f.path("sha256"))) matches.add(f.deepCopy());
            pin.put("comparison",matches.isEmpty()?"unknown":"bytes_match");
        }
        var release=MonitorFiles.object().put("sha256",fingerprint(releaseReport)).put("completed_at",releaseReport.path("completed_at").asText()); var joined=release.putObject("checks");
        for(String name:RELEASES) {
            JsonNode check=object(required(checks,name)); String outcome=text(required(check,"outcome")); require(Set.of("observed","unknown").contains(outcome),"invalid check outcome");
            var target=joined.putObject(name); if(outcome.equals("unknown")) {target.put("status","unknown");continue;}
            JsonNode observation=object(required(check,"observation")); if (!observed(name,observation)) { target.put("status","unknown"); continue; } target.put("status","observed");target.set("observation",observation.deepCopy());
            if(name.equals("nym")) {
                String tag=text(required(observation,"pinned_tag")); var files=(ArrayNode)pins.path("nym").path("matching_files"); target.put("pinned_bytes_comparison",!files.isEmpty() && pins.path("nym").path("pinned_tag").asText().equals(tag)?"matching_pin":"unknown");target.set("selected_files",files.deepCopy());
            } else if(name.equals("netty")) {
                String hash=text(required(observation,"sha256")); require(hash.matches("[0-9a-f]{64}"),"invalid Netty hash"); var matches=target.putArray("selected_files_with_matching_sha256");
                for(var entry:images.properties()) {JsonNode img=object(entry.getValue()); for(JsonNode f:array(required(img,"files"))) if(hash.equals(f.path("sha256").asText())) {var m=matches.addObject().put("role",entry.getKey()).put("image_id",text(required(img,"image_id")));m.set("image_path",required(f,"image_path").deepCopy());m.set("sha256",required(f,"sha256").deepCopy());}}
            } else if(name.equals("temurin")) {
                var matches=target.putArray("selected_java_release_metadata");for(var entry:images.properties()) {JsonNode img=object(entry.getValue());for(JsonNode f:array(required(img,"files"))) {JsonNode meta=f.path("java_release_metadata");if(!meta.isMissingNode()&&!meta.isNull()){var m=matches.addObject().put("role",entry.getKey()).put("image_id",text(required(img,"image_id")));m.set("image_path",required(f,"image_path").deepCopy());m.set("sha256",required(f,"sha256").deepCopy());m.set("metadata",meta.deepCopy());}}}
            } else if(name.equals("tor_package_metadata")) {
                JsonNode packages=object(required(observation,"packages"));var comparisons=target.putArray("selected_package_comparisons");for(JsonNode record:records) {if(!"tor".equals(record.path("role").asText())||!packages.has(record.path("name").asText()))continue;JsonNode pkg=object(packages.get(record.path("name").asText()));JsonNode source=required(pkg,"source"), published=required(pkg,"published");JsonNode sourceVersion=source.isNull()?NullNode.instance:required(source,"version"),publishedVersion=published.isNull()?NullNode.instance:required(published,"version");var c=comparisons.addObject();c.set("record",record.deepCopy());c.set("source_version",sourceVersion.deepCopy());c.set("published_version",publishedVersion.deepCopy());c.put("comparison",source.isNull()?"unknown":record.path("version").equals(sourceVersion)?"equal":"different");}
            } else {
                JsonNode expected=NullNode.instance;var relevant=target.putArray("selected_package_records"); if(name.equals("i2pd")) expected=required(observation,"noble_package_version"); else if(name.equals("quarkus")) expected=required(observation,"declared_version");
                boolean allEqual=true;for(JsonNode r:records) {String role=r.path("role").asText(), pkg=r.path("name").asText();if(name.equals("i2pd") && role.equals("i2p") && pkg.equals("i2pd") || name.equals("quarkus") && Set.of("app","sender").contains(role) && pkg.startsWith("io.quarkus:")){relevant.add(r.deepCopy());allEqual &= r.path("version").equals(expected);}}
                target.set("source_version_for_comparison",expected.deepCopy());target.put("comparison",relevant.isEmpty()||expected.isNull()?"unknown":allEqual?"all_equal":"different");
            }
        }
        var advisories=MonitorFiles.object(); var maven=new HashMap<String,List<JsonNode>>(); for(JsonNode record:records) if("Maven".equals(record.path("ecosystem").asText()) && record.path("name").isTextual()) maven.computeIfAbsent(record.path("name").asText(), ignored -> new ArrayList<>()).add(record); long matchedBytes=0;
        for(var pair:Map.of("netty","advisories","quarkus","quarkus_advisories").entrySet()) {
            JsonNode check=object(required(checks,pair.getValue()));String outcome=text(required(check,"outcome"));require(Set.of("observed","unknown").contains(outcome),"invalid advisory outcome");JsonNode obs=object(required(check,"observation"));String status=text(required(obs,"status"));require(status.equals(outcome),"inconsistent advisory status");
            var target=advisories.putObject(pair.getKey()).put("sha256",fingerprint(obs)).put("status",status);target.set("checked_at",required(obs,"checked_at").deepCopy());
            if(status.equals("unknown")){target.putNull("candidates");continue;}var candidates=target.putArray("candidates");
            for(JsonNode candidate:array(required(obs,"candidates"))) {
                object(candidate);var item=candidates.addObject();item.set("ghsa_id",required(candidate,"ghsa_id").deepCopy());item.set("cve_id",required(candidate,"cve_id").deepCopy());var matches=item.putArray("matches");
                for(JsonNode pkg:array(required(candidate,"packages"))) if("Maven".equals(pkg.path("ecosystem").asText()) && pkg.path("name").isTextual()) for(JsonNode record:maven.getOrDefault(pkg.path("name").asText(),List.of())) {var m=matches.addObject();m.set("package",pkg.deepCopy());m.set("record",record.deepCopy());matchedBytes += MonitorFiles.bytes(m).length; require(matchedBytes <= MonitorFiles.REPORT_LIMIT,"joined advisory evidence exceeds limit");}
                item.put("applicability","not_assessed");
            }
        }
        var candidateReport=report.deepCopy();candidateReport.set("pin_matches",pins);candidateReport.set("release",release);candidateReport.set("advisories",advisories);require(MonitorFiles.bytes(candidateReport).length <= MonitorFiles.REPORT_LIMIT,"runtime context report exceeds limit");report.set("pin_matches",pins);report.set("release",release);report.set("advisories",advisories);
    }
}
