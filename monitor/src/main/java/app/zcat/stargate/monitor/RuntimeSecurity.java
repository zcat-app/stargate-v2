// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.zip.*;

/** A bounded observation of selected, operator-supplied runtime evidence. */
final class RuntimeSecurity {
    private static final Set<String> ROLES = Set.of("app", "tor", "i2p", "nym", "sender");
    private static final String API = "https://api.osv.dev/v1/querybatch";
    private static final Pattern IMAGE = Pattern.compile("sha256:[0-9a-f]{64}"), NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"), COORD = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}");
    private static final int LIMIT = 32 * 1024 * 1024;
    interface Inspector { String inspect(List<String> names) throws Exception; }
    interface Query { JsonNode post(ArrayNode queries) throws Exception; }
    private static void require(boolean condition, String message) throws IOException { if (!condition) throw new IOException(message); }
    private static void fields(JsonNode value, String... names) throws IOException {
        require(value != null && value.isObject(), "object required");
        var actual = new HashSet<String>(); value.fieldNames().forEachRemaining(actual::add);
        require(actual.equals(Set.of(names)), "unexpected fields");
    }
    private static String str(JsonNode n) throws IOException {
        require(n != null && n.isTextual() && !n.textValue().isBlank() && n.textValue().chars().noneMatch(c -> c < 32), "text required"); return n.textValue();
    }
    private static String image(JsonNode n) throws IOException { String s = str(n); require(IMAGE.matcher(s).matches(), "invalid image ID"); return s; }
    private static byte[] read(Path path, int limit) throws IOException { return MonitorFiles.read(path.toAbsolutePath().normalize(), limit, false); }
    private static JsonNode parse(byte[] bytes) throws IOException { JsonNode n = MonitorFiles.JSON.readTree(bytes); require(n != null, "empty JSON"); return n; }
    private static JsonNode json(Path path, int limit) throws IOException { return parse(read(path, limit)); }
    private static Path path(JsonNode n) throws IOException { return Path.of(str(n)).toAbsolutePath().normalize(); }
    private static Instant stamp(JsonNode n) throws IOException { try { return OffsetDateTime.parse(str(n)).toInstant(); } catch (RuntimeException e) { throw new IOException("invalid timestamp", e); } }
    private static void version(JsonNode n) throws IOException { require(n != null && n.isIntegralNumber() && n.intValue() == 1, "invalid schema"); }
    private static String inspectDocker(List<String> names) throws Exception {
        var command = new ArrayList<>(List.of("/usr/bin/docker", "inspect", "--type", "container", "--format", "{{.Name}} {{.Id}} {{.Image}} {{.State.Running}}", "--")); command.addAll(names);
        Process p = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        // Drain concurrently so a malformed daemon response cannot block the timeout.
        var reader = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();
        try {
            var future = reader.submit(() -> p.getInputStream().readNBytes(8193));
            if (!p.waitFor(20, TimeUnit.SECONDS)) { p.destroyForcibly(); throw new IOException("Docker inspect timeout"); }
            byte[] data = future.get(2, TimeUnit.SECONDS); require(p.exitValue() == 0 && data.length <= 8192, "Docker inspect failed");
            for (byte b : data) require(b >= 0, "invalid Docker output");
            return new String(data, StandardCharsets.US_ASCII);
        } finally { p.destroyForcibly(); reader.shutdownNow(); }
    }
    private static JsonNode osvPost(ArrayNode queries) throws Exception {
        return post(URI.create(API),queries,Duration.ofSeconds(20));
    }
    static JsonNode post(URI endpoint,ArrayNode queries,Duration timeout) throws Exception {
        var body = MonitorFiles.object(); body.set("queries", queries);
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).followRedirects(HttpClient.Redirect.NEVER).build();
        var request = HttpRequest.newBuilder(endpoint).timeout(timeout).header("Content-Type", "application/json").header("Accept", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(MonitorFiles.bytes(body))).build();
        var future=client.sendAsync(request,info->new ReleaseCollectors.BoundedBody(4*1024*1024));
        try {var response=future.get(timeout.toMillis(),TimeUnit.MILLISECONDS);require(response.statusCode()==200,"OSV HTTP failure");return parse(response.body());}
        finally {future.cancel(true);client.shutdownNow();}
    }
    static ObjectNode collect(Path selection, Path runtimeContainers, Path dispositions, long maxAgeSeconds, Instant now, Path recorder) throws Exception {
        return collect(selection, runtimeContainers, dispositions, maxAgeSeconds, now, recorder, Path.of(System.getProperty("user.dir")));
    }
    static ObjectNode collect(Path selection, Path runtimeContainers, Path dispositions, long maxAgeSeconds, Instant now, Path recorder, Path sourceRoot) throws Exception {
        return collect(selection, runtimeContainers, dispositions, maxAgeSeconds, now, recorder, sourceRoot, RuntimeSecurity::inspectDocker, RuntimeSecurity::osvPost);
    }
    static ObjectNode collect(Path selection, Path runtimeContainers, Path dispositions, long maxAgeSeconds, Instant now, Path recorder, Inspector inspector, Query query) throws Exception {
        return collect(selection, runtimeContainers, dispositions, maxAgeSeconds, now, recorder, Path.of(System.getProperty("user.dir")), inspector, query);
    }
    static ObjectNode collect(Path selection, Path runtimeContainers, Path dispositions, long maxAgeSeconds, Instant now, Path recorder, Path sourceRoot, Inspector inspector, Query query) throws Exception {
        require(maxAgeSeconds > 0 && now != null, "positive identity freshness required");
        long started = System.nanoTime();
        MonitorFiles.directory(recorder, true);
        // Invalidate the previous report before attempting a new observation.
        MonitorFiles.replace(recorder.resolve("latest-security-binding.json"), MonitorFiles.object().put("status", "unknown"));
        MonitorFiles.replace(recorder.resolve("latest-runtime-identity.json"), MonitorFiles.object().put("status", "unknown"));
        byte[] rawSelection = read(selection, LIMIT); JsonNode root = parse(rawSelection);
        require(root.isObject() && (root.size() == 2 || root.size() == 3) && root.has("schema_version") && root.has("images") && (root.size() == 2 || root.has("source_graphs")), "invalid selection"); version(root.get("schema_version"));
        require(root.path("images").isArray() && !root.path("images").isEmpty(), "no selected images");
        JsonNode mapping = json(runtimeContainers, 65536); fields(mapping, "schema_version", "containers"); version(mapping.get("schema_version"));
        JsonNode containers = mapping.get("containers"); require(containers.isObject() && !containers.isEmpty(), "invalid container mapping");
        var sorted = new TreeMap<String, String>(); var unique = new HashSet<String>();
        var it = containers.fields(); while (it.hasNext()) { var e = it.next(); String name = str(e.getValue()); require(ROLES.contains(e.getKey()) && NAME.matcher(name).matches() && unique.add(name), "invalid container mapping"); sorted.put(e.getKey(), name); }
        String output = inspector.inspect(new ArrayList<>(sorted.values())); String[] lines = output.strip().split("\\R"); require(lines.length == sorted.size(), "incomplete Docker identity");
        var identity = MonitorFiles.object().put("schema_version", 1).put("checked_at", now.toString()); var ids = identity.putObject("images"); var containerIds = new HashSet<String>(); int line = 0;
        for (var e : sorted.entrySet()) { String[] f = lines[line++].trim().split("\\s+"); require(f.length == 4 && f[0].equals("/" + e.getValue()) && f[1].matches("[0-9a-f]{64}") && IMAGE.matcher(f[2]).matches() && f[3].equals("true") && containerIds.add(f[1]), "invalid Docker identity"); ids.put(e.getKey(), f[2]); }
        MonitorFiles.replace(recorder.resolve("latest-runtime-identity.json"), identity);
        var report = MonitorFiles.object().put("schema_version", 1).put("selection_sha256", MonitorFiles.hash(rawSelection));
        var images = report.putObject("images"); var records = report.putArray("package_records"); var findings = report.putArray("dispositions"); var selectedFiles = new HashMap<String, Map<String, FileEvidence>>();
        for (JsonNode entry : root.path("images")) {
            fields(entry, "role", "image_id", "scan", "files"); String role = str(entry.get("role")), id = image(entry.get("image_id"));
            require(ROLES.contains(role) && !images.has(role) && ids.has(role) && ids.path(role).asText().equals(id), "selected image differs from running container");
            require(entry.path("files").isArray() && entry.path("files").size() <= 10000, "invalid selected files");
            var image = images.putObject(role).put("image_id", id); var files = image.putArray("files"); var selected = new HashMap<String, FileEvidence>(); selectedFiles.put(role, selected);
            for (JsonNode file : entry.path("files")) { var evidence = file(file); require(selected.putIfAbsent(evidence.imagePath, evidence) == null, "duplicate image path"); files.add(evidence.value); for (JsonNode c : evidence.value.path("coordinates")) { var r = c.deepCopy(); ((ObjectNode)r).put("role",role).put("image_id",id).put("evidence","extracted_jar").put("image_path",evidence.imagePath).put("file_sha256",evidence.hash); records.add(r); } }
            require(entry.get("scan") != null && entry.get("scan").isTextual(), "selected scan required"); byte[] scanBytes = read(path(entry.get("scan")), LIMIT); JsonNode scanData = parse(scanBytes); ObjectNode scan = scan(scanData, id, MonitorFiles.hash(scanBytes), role, records, findings); image.set("scan", scan);
        }
        require(images.size() == ids.size(), "container roles differ from selection");
        sourceGraphs(root.path("source_graphs"), images, selectedFiles, records);
        supplemental(images, selectedFiles, records, sourceRoot);
        applyDispositions(dispositions, findings, report);
        report.putNull("release"); report.putObject("advisories"); report.putObject("pin_matches");
        var binding = report.putObject("deployment_binding").put("status", "observed").put("checked_at", now.toString()).put("sha256", MonitorFiles.fingerprint(identity)).put("reason", "selected image identities match observation");
        report.put("security_status", "not_assessed"); var limits = report.putArray("limitations");
        limits.add("Image file paths and their association with images are operator-supplied, not authenticated."); limits.add("Scanner packages and extracted metadata are partial inventories; applicability, backports, exposure and complete coverage are not assessed.");
        require(MonitorFiles.bytes(records).length <= 16 * 1024 * 1024, "inventory too large");
        var worker = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor(); ObjectNode observation;
        try { var future = worker.submit(() -> observe(records, query, now, started)); observation = future.get(60, TimeUnit.SECONDS); }
        finally { worker.shutdownNow(); }
        require(MonitorFiles.bytes(observation).length <= 16 * 1024 * 1024, "OSV output too large"); report.set("osv_observation", observation);
        Instant finished = now.plusNanos(System.nanoTime() - started); require(!finished.isBefore(now) && Duration.between(now, finished).compareTo(Duration.ofSeconds(maxAgeSeconds)) <= 0, "runtime identity stale after collection");
        binding.put("status", "observed"); require(MonitorFiles.bytes(report).length <= LIMIT, "binding too large"); MonitorFiles.replace(recorder.resolve("latest-security-binding.json"), report); return report;
    }
    private static String fileHash(Path p) throws Exception {
        p=p.toAbsolutePath().normalize(); MonitorFiles.directory(p.getParent(),false); var before=Files.readAttributes(p,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS); Object beforeCtime=Files.getAttribute(p,"unix:ctime",LinkOption.NOFOLLOW_LINKS); require(before.isRegularFile() && before.size()<=512L*1024*1024 && ((Number)MonitorFiles.attribute(p,"nlink")).intValue()==1,"invalid evidence file"); int uid=((Number)MonitorFiles.attribute(p,"uid")).intValue(), mode=((Number)MonitorFiles.attribute(p,"mode")).intValue(); require((uid==0 || uid==MonitorFiles.UID) && (mode & 0022)==0,"unsafe evidence permissions");
        MessageDigest digest=MessageDigest.getInstance("SHA-256"); try(var channel=FileChannel.open(p,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS); var in=Channels.newInputStream(channel)) { byte[] buffer=new byte[1024*1024]; long count=0; int n; while((n=in.read(buffer))!=-1) { count+=n; require(count<=512L*1024*1024,"evidence exceeds limit"); digest.update(buffer,0,n); } } var after=Files.readAttributes(p,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS); require(before.size()==after.size() && before.lastModifiedTime().equals(after.lastModifiedTime()) && Objects.equals(before.fileKey(),after.fileKey()) && Objects.equals(beforeCtime,Files.getAttribute(p,"unix:ctime",LinkOption.NOFOLLOW_LINKS)),"evidence changed during inspection"); return HexFormat.of().formatHex(digest.digest());
    }
    record FileEvidence(String imagePath, Path localPath, String hash, ObjectNode value) {}
    private static FileEvidence file(JsonNode entry) throws Exception {
        fields(entry, "image_path", "local_path"); String name = str(entry.get("image_path")); require(name.startsWith("/") && !Arrays.asList(name.split("/")).contains(".."), "invalid image path"); Path local = path(entry.get("local_path")); String hash = fileHash(local);
        var result = MonitorFiles.object().put("image_path",name).put("sha256",hash); var coords = result.putArray("coordinates"); result.putNull("java_release_metadata"); boolean incomplete = false;
        if (name.endsWith("/release") && Files.size(local) <= 16384) { var data = new HashMap<String,String>(); boolean valid = true; for (String l : new String(read(local,16384), StandardCharsets.UTF_8).split("\\R")) { var m = Pattern.compile("([A-Z][A-Z0-9_]*)=\"([^\"\\\\]*)\"").matcher(l); if (m.matches() && data.putIfAbsent(m.group(1),m.group(2)) != null) valid = false; } if (valid && data.containsKey("JAVA_VERSION")) { var meta = result.putObject("java_release_metadata"); for (String k : List.of("JAVA_VERSION","IMPLEMENTOR","OS_ARCH")) if (data.containsKey(k)) meta.put(k,data.get(k)); } }
        if (name.endsWith(".jar")) {
            var seen = new HashSet<String>(); int entries = 0, matches = 0; try (var zip = new ZipFile(local.toFile())) { var zipEntries = zip.entries(); while (zipEntries.hasMoreElements()) { ZipEntry z = zipEntries.nextElement(); require(++entries <= 100000, "too many jar entries"); String n = z.getName(); if (!n.startsWith("META-INF/maven/") || !n.endsWith("/pom.properties")) continue; require(++matches <= 1000 && seen.add(n), "duplicate jar metadata"); byte[] metadata; try (var stream = zip.getInputStream(z)) { metadata = stream.readNBytes(16385); } require(metadata.length <= 16384, "oversized jar metadata"); try { for (byte octet : metadata) if (octet < 0) throw new IllegalArgumentException(); var props = new HashMap<String,String>(); for (String l : new String(metadata,StandardCharsets.US_ASCII).split("\\R")) { l=l.trim(); if (l.isEmpty() || l.startsWith("#") || l.startsWith("!")) continue; int equals=l.indexOf('='); if (equals<0 || l.contains("\\")) throw new IllegalArgumentException(); String k=l.substring(0,equals).trim(), v=l.substring(equals+1).trim(); if (props.putIfAbsent(k,v)!=null) throw new IllegalArgumentException(); } String g=props.get("groupId"), a=props.get("artifactId"), v=props.get("version"); if (g==null || a==null || v==null || !COORD.matcher(g).matches() || !COORD.matcher(a).matches() || !COORD.matcher(v).matches() || !n.equals("META-INF/maven/"+g+"/"+a+"/pom.properties")) throw new IllegalArgumentException(); coords.addObject().put("ecosystem","Maven").put("name",g+":"+a).put("version",v).put("metadata_entry",n); } catch (IllegalArgumentException ex) { incomplete=true; } } } incomplete |= coords.isEmpty();
        }
        require(fileHash(local).equals(hash), "file changed during inspection"); result.put("jar_metadata_incomplete",incomplete); return new FileEvidence(name,local,hash,result);
    }
    private static ObjectNode scan(JsonNode data, String id, String hash, String role, ArrayNode records, ArrayNode dispositions) throws Exception {
        // Trivy 0.76.1 report.go: ArtifactID hashes image plus repository context;
        // Metadata.ImageID is the Docker configuration image identity.
        require(data.isObject() && data.path("SchemaVersion").isIntegralNumber() && data.path("SchemaVersion").intValue()==2 && "container_image".equals(data.path("ArtifactType").asText()) && IMAGE.matcher(str(data.get("ArtifactID"))).matches() && id.equals(image(data.path("Metadata").get("ImageID"))), "scan image identity mismatch");
        String version=str(data.path("Trivy").get("Version")); require(version.matches("[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?"), "invalid Trivy version"); String created=str(data.get("CreatedAt")); stamp(data.get("CreatedAt")); require(data.path("Results").isArray(), "missing scan results");
        var result=MonitorFiles.object().put("schema_version",1); result.putObject("source_binding").put("selected_image_id",id).put("artifact_id",data.path("ArtifactID").asText()).put("metadata_image_id",id).put("trivy_json_sha256",hash).put("scanner","Trivy").put("scanner_version",version).put("scan_created_at",created);
        var scanner=result.putObject("scanner_findings"); var counts=scanner.putObject("severity_counts"); var found=scanner.putArray("records"); var targets=result.putArray("targets"); boolean os=false,java=false,rust=false; int index=0;
        for (JsonNode target:data.path("Results")) {
            String targetName=str(target.get("Target")), cls=str(target.get("Class")), type=str(target.get("Type")); os |= cls.equals("os-pkgs"); java |= cls.equals("lang-pkgs") && type.equals("jar"); rust |= cls.equals("lang-pkgs") && type.equals("cargo"); JsonNode packages=target.get("Packages"), vulnerabilities=target.get("Vulnerabilities"); require(packages==null || packages.isArray(),"invalid packages"); require(vulnerabilities==null || vulnerabilities.isArray(),"invalid vulnerabilities");
            var summary=targets.addObject().put("target",targetName).put("class",cls).put("type",type); if (packages==null) summary.putNull("scanner_package_count"); else summary.put("scanner_package_count",packages.size()); summary.put("scanner_finding_count",vulnerabilities==null?0:vulnerabilities.size());
            if (packages!=null) for (JsonNode p:packages) { String name=str(p.get("Name")), v=str(p.get("Version")); if(cls.equals("os-pkgs")) v=packageVersion(p,"",v); var r=records.addObject().put("role",role).put("image_id",id).put("evidence","scanner_package").put("target_index",index); if(cls.equals("lang-pkgs") && type.equals("jar")) r.put("ecosystem","Maven"); else r.putNull("ecosystem"); r.put("name",name).put("version",v); JsonNode osInfo=data.path("Metadata").path("OS"); if(cls.equals("os-pkgs") && "ubuntu".equals(osInfo.path("Family").asText()) && "24.04".equals(osInfo.path("Name").asText()) && p.path("SrcName").isTextual() && p.path("SrcVersion").isTextual()) { String sourceName=str(p.get("SrcName")), sourceVersion=packageVersion(p,"Src",str(p.get("SrcVersion"))); r.putObject("source_package").put("ecosystem","Ubuntu:24.04:LTS").put("name",sourceName).put("version",sourceVersion); } else r.putNull("source_package"); }
            if(vulnerabilities!=null) for(JsonNode f:vulnerabilities) { String severity=str(f.get("Severity")); require(Set.of("UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL").contains(severity), "invalid severity"); var finding=found.addObject().put("target_index",index).put("id",str(f.get("VulnerabilityID"))).put("package",str(f.get("PkgName"))).put("installed_version",str(f.get("InstalledVersion"))).put("scanner_severity",severity); counts.put(severity,counts.path(severity).asInt()+1); var d=dispositions.addObject().put("role",role).put("image_id",id).put("scan_sha256",hash); d.set("finding",finding.deepCopy()); d.put("status","retained_unassessed").putNull("note"); d.putArray("evidence"); }
            index++;
        }
        scanner.put("count",found.size()); result.putObject("coverage").put("os_package_result_emitted",os).put("java_archive_result_emitted",java).put("rust_result_emitted",rust); result.putArray("limitations").add("Supplied scanner output is not independent proof of image bytes, complete inventory, or vulnerability applicability."); return result;
    }
    private static String packageVersion(JsonNode p,String prefix,String v) throws IOException { JsonNode epoch=p.get(prefix+"Epoch"), release=p.get(prefix+"Release"); if(epoch!=null) { require((epoch.isTextual() || epoch.isIntegralNumber()) && epoch.asText().matches("[0-9]+"),"invalid epoch"); if(!epoch.asText().equals("0")) v=epoch.asText()+":"+v; } if(release!=null) v+="-"+str(release); return v; }
    private static void sourceGraphs(JsonNode graphs, ObjectNode images, Map<String,Map<String,FileEvidence>> files, ArrayNode records) throws Exception {
        if(graphs.isMissingNode()) return; require(graphs.isArray() && graphs.size()<=1,"invalid source graphs"); for(JsonNode g:graphs) { fields(g,"role","binary_image_path","build_metadata_image_path","graph_path"); require("nym".equals(str(g.get("role"))) && images.has("nym"),"invalid graph role"); var selected=files.get("nym"); FileEvidence binary=selected.get(str(g.get("binary_image_path"))), build=selected.get(str(g.get("build_metadata_image_path"))); require(binary!=null && build!=null,"missing graph files"); byte[] buildBytes=read(build.localPath,LIMIT), graphBytes=read(path(g.get("graph_path")),LIMIT); JsonNode b=parse(buildBytes), graph=parse(graphBytes); require(MonitorFiles.hash(buildBytes).equals(build.hash) && binary.hash.equals(b.path("binarySha256").asText()) && graph.path("sourceCommit").asText().matches("[0-9a-f]{40}") && graph.path("sourceCommit").equals(b.path("sourceCommit")) && graph.path("cargoLockSha256").asText().matches("[0-9a-f]{64}") && graph.path("cargoLockSha256").equals(b.path("cargoLockSha256")) && graph.path("selectedGraphSha256").asText().matches("[0-9a-f]{64}") && graph.path("packages").isArray() && graph.path("packages").size()<=5000,"invalid source graph binding"); int count=0; for(JsonNode p:graph.path("packages")) { require(p.isObject(),"invalid source package"); if(!"registry+https://github.com/rust-lang/crates.io-index".equals(p.path("source").asText())) continue; String name=str(p.get("name")), version=str(p.get("version")); require(COORD.matcher(name).matches() && COORD.matcher(version).matches(),"invalid source coordinate"); records.addObject().put("role","nym").put("image_id",images.path("nym").path("image_id").asText()).put("evidence","nym_source_graph").put("ecosystem","crates.io").put("name",name).put("version",version).put("binary_image_path",binary.imagePath).put("binary_sha256",binary.hash).put("build_metadata_sha256",build.hash).put("source_graph_sha256",MonitorFiles.hash(graphBytes)); count++; } require(count>0,"no source packages"); }
    }
    private static void supplemental(ObjectNode images, Map<String,Map<String,FileEvidence>> files, ArrayNode records, Path sourceRoot) throws Exception {
        if (!images.has("sender")) return; Path manifest=sourceRoot.toAbsolutePath().normalize().resolve("containers/simplex-alert/libraries.json"); byte[] bytes=ReleaseCollectors.read(manifest,LIMIT); JsonNode libraries=parse(bytes).path("libraries"); require(libraries.isArray(),"invalid library manifest"); var source=Map.of("libssl3t64","openssl","libgmp10","gmp"); for(JsonNode lib:libraries) { String pkg=str(lib.get("package")); require(source.containsKey(pkg),"unknown library mapping"); FileEvidence f=files.get("sender").get(str(lib.get("path"))); if(f!=null && f.hash.equals(str(lib.get("sha256")))) { String version=str(lib.get("version")); var r=records.addObject().put("role","sender").put("image_id",images.path("sender").path("image_id").asText()).put("evidence","supplemental_library_manifest_hash_match").put("image_path",f.imagePath).put("file_sha256",f.hash).put("manifest_sha256",MonitorFiles.hash(bytes)).put("ecosystem","Ubuntu:24.04:LTS").put("name",pkg).put("version",version); r.putObject("source_package").put("ecosystem","Ubuntu:24.04:LTS").put("name",source.get(pkg)).put("version",version); } }
    }
    private static void applyDispositions(Path path, ArrayNode findings, ObjectNode report) throws Exception {
        if(path==null) { report.putNull("dispositions_sha256"); return; } byte[] raw=read(path,LIMIT); JsonNode root=parse(raw); fields(root,"schema_version","dispositions"); version(root.get("schema_version")); require(root.path("dispositions").isArray(),"invalid dispositions"); var seen=new HashSet<String>(); for(JsonNode d:root.path("dispositions")) { fields(d,"role","image_id","scan_sha256","target_index","id","package","installed_version","status","note","evidence_files"); require(Set.of("retained_unassessed","backport_evidence","component_absence_evidence","other_operator_assessment").contains(str(d.get("status"))) && str(d.get("note")).length()<=4096 && d.path("evidence_files").isArray() && !d.path("evidence_files").isEmpty(),"invalid disposition"); var matches=new ArrayList<ObjectNode>(); for(JsonNode f:findings) { boolean same=true; for(String k:List.of("role","image_id","scan_sha256")) same &= Objects.equals(d.get(k),f.get(k)); for(String k:List.of("target_index","id","package","installed_version")) same &= Objects.equals(d.get(k),f.path("finding").get(k)); if(same) matches.add((ObjectNode)f); } require(matches.size()==1 && seen.add(MonitorFiles.JSON.writeValueAsString(List.of(d.get("role"),d.get("target_index"),d.get("id"),d.get("package"),d.get("installed_version")))),"disposition not unique"); ObjectNode match=matches.get(0); match.put("status",str(d.get("status"))).put("note",str(d.get("note"))); var evidence=match.putArray("evidence"); for(JsonNode e:d.path("evidence_files")) evidence.addObject().put("sha256",fileHash(path(e))); } report.put("dispositions_sha256",MonitorFiles.hash(raw));
    }
    private static ObjectNode observe(ArrayNode records, Query request, Instant now, long started) throws Exception {
        require(records.size()<=50000,"too many package records"); var coordinates=new TreeMap<String,ArrayNode>(); for(JsonNode r:records) { JsonNode p=Set.of("Maven","crates.io").contains(r.path("ecosystem").asText())?r:r.path("source_package"); String eco=p.path("ecosystem").asText(); if(!Set.of("Maven","Ubuntu:24.04:LTS","crates.io").contains(eco)) continue; String name=str(p.get("name")), version=str(p.get("version")); require(name.matches("[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}") && version.matches("[A-Za-z0-9][A-Za-z0-9._+~:-]{0,255}"),"invalid OSV coordinate"); String key=eco+"\u0000"+name+"\u0000"+version; var refs=coordinates.computeIfAbsent(key,k->MonitorFiles.JSON.createArrayNode()); refs.addObject().put("role",str(r.get("role"))).put("image_id",image(r.get("image_id"))).put("evidence",str(r.get("evidence"))); } require(!coordinates.isEmpty() && coordinates.size()<=5000,"invalid OSV query count");
        var out=MonitorFiles.object().put("status","observed").put("checked_at",now.toString()).put("source",API); var results=out.putArray("queries"); var keys=new ArrayList<>(coordinates.keySet()); for(int offset=0;offset<keys.size();offset+=100) { int end=Math.min(offset+100,keys.size()); var queries=MonitorFiles.JSON.createArrayNode(); for(String key:keys.subList(offset,end)) { String[] parts=key.split("\u0000",-1); var q=queries.addObject(); q.putObject("package").put("ecosystem",parts[0]).put("name",parts[1]); q.put("version",parts[2]); } JsonNode response=request.post(queries); fields(response,"results"); require(response.path("results").isArray() && response.path("results").size()==end-offset,"incomplete OSV response"); for(int i=offset;i<end;i++) { String[] parts=keys.get(i).split("\u0000",-1); JsonNode item=response.path("results").get(i-offset); require(item.isObject() && (item.isEmpty() || item.size()==1 && item.has("vulns")) && (!item.has("vulns") || item.path("vulns").isArray()),"invalid or paginated OSV result"); var result=results.addObject().put("ecosystem",parts[0]).put("name",parts[1]).put("version",parts[2]); result.set("selected_records",coordinates.get(keys.get(i))); var candidates=result.putArray("candidates"); var seen=new HashSet<String>(); for(JsonNode v:item.path("vulns")) { fields(v,"id","modified"); String id=str(v.get("id")), modified=str(v.get("modified")); require(id.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}") && modified.length()<=80 && !stamp(v.get("modified")).isAfter(now.plusNanos(System.nanoTime() - started)) && seen.add(id) && candidates.size()<3000,"invalid OSV candidate"); candidates.addObject().put("id",id).put("modified",modified); } } }
        out.put("checked_at",now.plusNanos(System.nanoTime() - started).toString()); out.put("scope","Exact supplied coordinates only; package applicability, completeness, backports and exposure are not assessed."); return out;
    }
}
