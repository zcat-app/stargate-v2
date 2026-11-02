// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.*;
import java.time.format.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
import java.util.regex.*;
import java.util.zip.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;

/** Source release publications are observations, never a deployment or security assessment. */
final class ReleaseCollectors {
    static final String NYM = "https://api.github.com/repos/nymtech/nym/releases";
    static final String I2PD = "https://api.github.com/repos/PurpleI2P/i2pd/releases";
    static final String QUARKUS = "https://repo.maven.apache.org/maven2/io/quarkus/platform/quarkus-bom/maven-metadata.xml";
    static final String TEMURIN = "https://api.adoptium.net/v3/assets/latest/25/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse";
    static final String TOR_BASE = "https://deb.torproject.org/torproject.org/";
    static final String TOR = TOR_BASE + "dists/noble/main/binary-amd64/Packages";
    static final String AGE = "https://api.github.com/repos/FiloSottile/age/releases/latest";
    static final String NETTY_SCOPE = "Embedded metadata in the selected JAR only; completeness, authenticity, deployment and security are not established.";
    static final String AGE_SCOPE = "Literal tag equality with the API-selected latest release only; version ordering, deployment, artifact authenticity and security are not assessed.";
    static final String TOR_SCOPE = "Literal metadata equality only; version ordering, signed APT authenticity, advisories, package bytes and deployment are not assessed.";
    static final int LIMIT = 2 * 1024 * 1024;
    static final String NUM = "(?:0|[1-9][0-9]{0,8})";
    static final Pattern FINAL = Pattern.compile("(" + NUM + ")\\.(" + NUM + ")\\.(" + NUM + ")(?:\\.(" + NUM + "))?");
    static final Pattern NYM_TAG = Pattern.compile("nym-binaries-v(20[0-9]{2})\\.([0-9]{1,3})-([a-z0-9]+(?:-[a-z0-9]+)*)");
    static final Pattern I2PD_TAG = Pattern.compile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    static final Pattern AGE_TAG = Pattern.compile("v(?:0|[1-9][0-9]{0,5})\\.(?:0|[1-9][0-9]{0,5})\\.(?:0|[1-9][0-9]{0,5})");
    static final Pattern GHSA = Pattern.compile("GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}");
    static final String NS = "http://maven.apache.org/POM/4.0.0";
    record Response(byte[] bytes, String link) {}
    interface Fetcher { Response get(String url, int limit) throws Exception; }
    interface Observation { void run(ObjectNode value) throws Exception; }
    static final class Invalid extends IOException { Invalid(String message) { super(message); } }
    static void require(boolean condition, String reason) throws Invalid { if (!condition) throw new Invalid(reason); }
    static String reason(Exception e) { return e instanceof Invalid ? e.getMessage() : "observation failed"; }
    static String stamp(Instant now) { return now.truncatedTo(ChronoUnit.SECONDS).toString(); }
    static String text(JsonNode n) throws Invalid { require(n != null && n.isTextual(), "invalid text field"); return n.textValue(); }
    static boolean matches(String value, Pattern pattern) { return value != null && pattern.matcher(value).matches(); }
    static byte[] read(Path path, int limit) throws IOException {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS), "input is not a regular file");
        try (var channel = Files.newByteChannel(path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)); var input = java.nio.channels.Channels.newInputStream(channel)) {
            byte[] bytes = input.readNBytes(limit + 1); require(bytes.length <= limit, "input exceeds byte limit"); return bytes;
        }
    }
    static JsonNode json(byte[] raw) throws IOException { JsonNode n = MonitorFiles.JSON.readTree(raw); require(n != null, "empty JSON"); return n; }
    static String utf8(byte[] raw) throws CharacterCodingException { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString(); }
    static String date(String value) throws Invalid {
        try { require(value.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"), "invalid timestamp"); require(Instant.parse(value).toString().equals(value), "invalid timestamp"); return value; }
        catch (DateTimeException e) { throw new Invalid("invalid timestamp"); }
    }
    static ObjectNode base(String source, Instant now) { return MonitorFiles.object().put("schema_version", 1).put("source", source).put("security_status", "not_assessed").put("checked_at", stamp(now)).put("status", "unknown"); }
    static void check(ObjectNode checks, String name, ObjectNode initial, Observation observation) {
        try { observation.run(initial); }
        catch (Exception e) {
            if (name.equals("temurin")) initial.putObject("upstream").put("status", "unknown");
            else initial.put("status", "unknown").put("reason", reason(e));
        }
        boolean unknown = initial.path("status").asText().equals("unknown") || initial.path("metadata_status").asText().equals("unknown") || (name.equals("temurin") && (initial.path("source_baseline").path("version").isNull() || !initial.path("upstream").path("status").asText().equals("observed")));
        var result = checks.putObject(name).put("outcome", unknown ? "unknown" : "observed"); result.set("observation", initial);
    }
    static ObjectNode collect(Path sourceRoot, Path nettyJar, String family, String temurinDeployment, String ageTag, Instant now) throws Exception {
        return collect(sourceRoot, nettyJar, family, temurinDeployment, ageTag, now, ReleaseCollectors::fetch);
    }
    static ObjectNode collect(Path root, Path nettyJar, String family, String deployment, String ageTag, Instant now, Fetcher get) throws Exception {
        Objects.requireNonNull(root); Objects.requireNonNull(now); Objects.requireNonNull(get);
        var report = MonitorFiles.object().put("schema_version", 1).put("completed_at", stamp(now)).put("security_status", "not_assessed").put("deployment_status", "not_assessed");
        var checks = report.putObject("checks");
        var nym = base(NYM, now).putNull("pinned_tag").putNull("latest_tag").putNull("release_url");
        check(checks, "nym", nym, out -> {
            JsonNode manifest = json(read(root.resolve("containers/nym-release.json"), LIMIT)); require(manifest.isObject(), "invalid manifest");
            String pin = text(manifest.get("tag")); require(matches(pin, NYM_TAG), "unsupported binary release tag"); out.put("pinned_tag", pin);
            var releases = releases(NYM, 100, 10, true, get); String latest = latest(releases, pin); require(matches(latest, NYM_TAG), "unsupported binary release tag");
            out.put("status", latest.equals(pin) ? "current" : "newer_release").put("latest_tag", latest).put("release_url", "https://github.com/nymtech/nym/releases/tag/" + latest);
        });
        var i2pd = base(I2PD, now).putNull("package_release_tag").putNull("noble_package_version").putNull("latest_tag").putNull("latest_published_at").putNull("release_url");
        check(checks, "i2pd", i2pd, out -> {
            JsonNode manifest = json(read(root.resolve("containers/i2p-packages.json"), LIMIT)); require(manifest.isArray() && manifest.size() == 1 && manifest.get(0).isObject(), "invalid package manifest");
            String version = text(manifest.get(0).get("version")); var m = Pattern.compile("([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})-([0-9]{1,3}noble[0-9]{1,3})").matcher(version); require(m.matches(), "unsupported package declaration");
            String pin = m.group(1); require(manifest.get(0).path("url").asText().equals("https://github.com/PurpleI2P/i2pd/releases/download/" + pin + "/i2pd_" + version + "_amd64.deb"), "unsupported package declaration");
            out.put("package_release_tag", pin).put("noble_package_version", version); var releases = releases(I2PD, 10, 20, false, get); String latest = latest(releases, pin); require(matches(latest, I2PD_TAG), "unsupported latest release tag");
            out.put("status", latest.equals(pin) ? "current" : "newer_release").put("latest_tag", latest).put("latest_published_at", releases.get(latest)).put("release_url", "https://github.com/PurpleI2P/i2pd/releases/tag/" + latest);
        });
        var quarkus = base(QUARKUS, now).put("family", family).putNull("declared_version");
        check(checks, "quarkus", quarkus, out -> { String pin = quarkusPin(root, family); out.put("declared_version", pin); out.setAll(quarkusCompare(pin, family, get.get(QUARKUS, LIMIT).bytes)); });
        var temurin = MonitorFiles.object().put("observed_at_utc", stamp(now)).put("operator_reported_deployment_build", deployment);
        temurin.putObject("selection").put("vendor", "temurin").put("feature", "25").put("os", "linux").put("architecture", "x64").put("image", "jdk").put("jvm", "hotspot");
        var baseline = temurin.putObject("source_baseline").putNull("version").put("source", "containers/java-runtime.json"); temurin.putObject("upstream").put("status", "unknown");
        check(checks, "temurin", temurin, out -> {
            require(deployment == null || deployment.matches("[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}"), "invalid deployment build");
            try { baseline.put("version", javaBaseline(read(root.resolve("containers/java-runtime.json"), LIMIT))); } catch (Exception ignored) { /* explicit null baseline */ }
            out.set("upstream", temurin(json(get.get(TEMURIN, 100000).bytes)));
        });
        var netty = MonitorFiles.object().put("artifact", nettyJar == null ? null : nettyJar.toString()).putNull("sha256").put("metadata_status", "unknown").put("scope", NETTY_SCOPE); netty.putArray("modules"); netty.putArray("unsupported_metadata_entries");
        check(checks, "netty", netty, out -> { require(nettyJar != null, "Netty JAR was not selected"); out.setAll(netty(nettyJar)); });
        var tor = torBase(root.resolve("containers/tor-packages.json"), now);
        check(checks, "tor_package_metadata", tor, out -> torObserve(out, root.resolve("containers/tor-packages.json"), get));
        var age = base(AGE, now).put("selected_tag", ageTag).put("comparison", "unknown").putNull("latest_tag").putNull("latest_created_at").putNull("latest_published_at").putNull("release_url").put("scope", AGE_SCOPE);
        check(checks, "age", age, out -> {
            require(matches(ageTag, AGE_TAG), "invalid selected age tag"); JsonNode item = json(get.get(AGE, 512 * 1024).bytes); String latest = text(item.get("tag_name"));
            require(item.isObject() && matches(latest, AGE_TAG) && item.path("draft").isBoolean() && !item.path("draft").booleanValue() && item.path("prerelease").isBoolean() && !item.path("prerelease").booleanValue() && item.path("html_url").asText().equals("https://github.com/FiloSottile/age/releases/tag/" + latest), "unsupported release metadata");
            String created = date(text(item.get("created_at"))), published = date(text(item.get("published_at"))); require(!Instant.parse(created).isAfter(now) && !Instant.parse(published).isAfter(now), "future release timestamp");
            out.put("status", "observed").put("comparison", latest.equals(ageTag) ? "equal" : "different").put("latest_tag", latest).put("latest_created_at", created).put("latest_published_at", published).put("release_url", "https://github.com/FiloSottile/age/releases/tag/" + latest);
        });
        for (String repo : List.of("netty/netty", "quarkusio/quarkus")) {
            var advisory = base("https://api.github.com/repos/" + repo + "/security-advisories", now).putNull("candidates");
            if (repo.startsWith("quarkus")) advisory.put("applicability_status", "not_assessed");
            check(checks, repo.startsWith("netty") ? "advisories" : "quarkus_advisories", advisory, out -> { ArrayNode candidates = advisories(repo, get); out.set("candidates", candidates); out.put("status", "observed"); });
        }
        boolean unknown = false; for (String name : List.of("nym", "i2pd", "quarkus", "temurin", "netty", "tor_package_metadata", "age")) unknown |= !checks.path(name).path("outcome").asText().equals("observed"); report.put("outcome", unknown ? "unknown" : "observed"); return report;
    }

    static Map<String, String> releases(String endpoint, int perPage, int maxPages, boolean nym, Fetcher get) throws Exception {
        var found = new HashMap<String, String>();
        for (int page = 1; page <= maxPages; page++) {
            String url = endpoint + "?per_page=" + perPage + (page == 1 ? "" : "&page=" + page); Response response = get.get(url, LIMIT); require(response.bytes.length <= LIMIT, "response too large"); JsonNode items = json(response.bytes);
            require(items.isArray() && items.size() <= perPage, "invalid releases response");
            for (JsonNode item : items) {
                require(item.isObject() && item.path("tag_name").isTextual() && item.path("draft").isBoolean() && item.path("prerelease").isBoolean(), "invalid release entry");
                String tag = item.path("tag_name").textValue(); if (item.path("draft").booleanValue() || item.path("prerelease").booleanValue() || (nym && !tag.startsWith("nym-binaries-"))) continue;
                String published = date(text(item.get("published_at"))); require(found.putIfAbsent(tag, published) == null, "duplicate release tag");
            }
            String next = releaseNext(response.link, endpoint, perPage, page, nym); require(next != null || items.size() < perPage, "possibly incomplete release list");
            if (next == null) return found;
        }
        throw new Invalid("pagination limit reached");
    }
    static String latest(Map<String, String> releases, String pin) throws Invalid {
        require(releases.containsKey(pin), "pinned tag absent from complete release list"); String date = Collections.max(releases.values()); var newest = releases.entrySet().stream().filter(e -> e.getValue().equals(date)).map(Map.Entry::getKey).toList(); require(newest.size() == 1, "ambiguous latest publication"); return newest.getFirst();
    }
    static String linkNext(String link) throws Invalid {
        if (link == null) return null; require(!link.isEmpty() && link.length() <= 8192, "invalid pagination header"); String next = null;
        for (String part : link.split(",", -1)) { var m = Pattern.compile("\\s*<([^<>]+)>\\s*;\\s*rel=\"([a-z]+)\"\\s*").matcher(part); require(m.matches(), "invalid pagination header"); if (m.group(2).equals("next")) { require(next == null, "ambiguous pagination"); next = m.group(1); } }
        return next;
    }
    static URI githubUri(String url) throws Invalid {
        try { require(url.chars().allMatch(c -> c >= 33 && c <= 126), "invalid pagination URL"); URI uri = URI.create(url); require("https".equals(uri.getScheme()) && "api.github.com".equals(uri.getRawAuthority()) && uri.getRawFragment() == null, "unsafe pagination URL"); return uri; }
        catch (IllegalArgumentException e) { throw new Invalid("invalid pagination URL"); }
    }
    static Map<String, String> query(URI uri) throws Invalid {
        require(uri.getRawQuery() != null, "invalid pagination URL"); var query = new HashMap<String, String>();
        try { for (String part : uri.getRawQuery().split("&", -1)) { String[] pair = part.split("=", 2); require(pair.length == 2, "invalid pagination URL"); String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8), value = URLDecoder.decode(pair[1], StandardCharsets.UTF_8); require(!value.isEmpty() && query.putIfAbsent(key, value) == null, "invalid pagination URL"); } }
        catch (IllegalArgumentException e) { throw new Invalid("invalid pagination URL"); } return query;
    }
    static String releaseNext(String link, String endpoint, int count, int page, boolean nym) throws Invalid {
        String next = linkNext(link); if (next == null) return null; URI uri = githubUri(next); String path = uri.getRawPath();
        require(path.equals(URI.create(endpoint).getRawPath()) || (nym ? path.equals("/repositories/232312458/releases") : path.matches("/repositories/[0-9]+/releases")), "unsafe pagination URL");
        require(query(uri).equals(Map.of("per_page", Integer.toString(count), "page", Integer.toString(page + 1))), "unexpected pagination URL"); return next;
    }

    static Element xml(byte[] bytes) throws Exception {
        require(bytes.length <= LIMIT && !new String(bytes, StandardCharsets.ISO_8859_1).contains("<!"), "oversized or unsupported XML"); for (byte b : bytes) require(b != 0, "unsupported XML encoding");
        var factory = DocumentBuilderFactory.newInstance(); factory.setNamespaceAware(true); factory.setXIncludeAware(false); factory.setExpandEntityReferences(false); factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); factory.setFeature("http://xml.org/sax/features/external-general-entities", false); factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false); factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, ""); factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        var builder = factory.newDocumentBuilder(); builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() { @Override public void error(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; } @Override public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; } });
        return builder.parse(new ByteArrayInputStream(bytes)).getDocumentElement();
    }
    static List<Element> children(Element parent, String name, String namespace) {
        var result = new ArrayList<Element>(); for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) if (n instanceof Element e && e.getLocalName().equals(name) && Objects.equals(e.getNamespaceURI(), namespace)) result.add(e); return result;
    }
    static Element one(Element parent, String name, String ns) throws Invalid { var values = children(parent, name, ns); require(values.size() == 1, "missing or ambiguous XML field"); return values.getFirst(); }
    static String field(Element parent, String name, String ns) throws Invalid { var e = one(parent, name, ns); for (Node n = e.getFirstChild(); n != null; n = n.getNextSibling()) require(!(n instanceof Element), "invalid XML field"); String value = e.getTextContent().strip(); require(!value.isEmpty(), "empty XML field"); return value; }
    static List<Integer> version(String value) throws Invalid { var m = FINAL.matcher(value); require(m.matches(), "unsupported final version"); return List.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)), m.group(4) == null ? 0 : Integer.parseInt(m.group(4))); }
    static int versionCompare(List<Integer> a, List<Integer> b) { for (int i = 0; i < 4; i++) { int c = a.get(i).compareTo(b.get(i)); if (c != 0) return c; } return 0; }
    static String quarkusPin(Path root, String family) throws Exception {
        require(family != null && family.matches(NUM + "\\." + NUM), "unsupported family"); Element pom = xml(read(root.resolve("pom.xml"), LIMIT)); require("project".equals(pom.getLocalName()) && NS.equals(pom.getNamespaceURI()), "unexpected POM root"); Element props = one(pom, "properties", NS);
        require(field(props, "quarkus.platform.group-id", NS).equals("io.quarkus.platform") && field(props, "quarkus.platform.artifact-id", NS).equals("quarkus-bom"), "unexpected BOM coordinates"); String pin = field(props, "quarkus.platform.version", NS); version(pin); require(pin.startsWith(family + "."), "declared version is outside specified family");
        var imports = children(one(one(pom, "dependencyManagement", NS), "dependencies", NS), "dependency", NS); require(imports.size() == 1, "unexpected or ambiguous BOM import"); Element dep = imports.getFirst(); String[] names = {"groupId", "artifactId", "version", "type", "scope"}, values = {"${quarkus.platform.group-id}", "${quarkus.platform.artifact-id}", "${quarkus.platform.version}", "pom", "import"}; for (int i = 0; i < names.length; i++) require(field(dep, names[i], NS).equals(values[i]), "unexpected BOM import"); return pin;
    }
    static ObjectNode quarkusCompare(String pin, String family, byte[] bytes) throws Exception {
        Element root = xml(bytes); require("metadata".equals(root.getLocalName()) && root.getNamespaceURI() == null && field(root, "groupId", null).equals("io.quarkus.platform") && field(root, "artifactId", null).equals("quarkus-bom"), "unexpected metadata coordinates"); Element versioning = one(root, "versioning", null); String updated = field(versioning, "lastUpdated", null);
        require(updated.matches("[0-9]{14}"), "invalid metadata timestamp"); String timestamp; try { timestamp = LocalDateTime.parse(updated, DateTimeFormatter.ofPattern("uuuuMMddHHmmss").withResolverStyle(ResolverStyle.STRICT)).toInstant(ZoneOffset.UTC).toString(); } catch (DateTimeException e) { throw new Invalid("invalid metadata timestamp"); }
        Element entries = one(versioning, "versions", null); var seen = new HashSet<String>(); var finals = new TreeMap<List<Integer>, String>(ReleaseCollectors::versionCompare); int count = 0;
        for (Node node = entries.getFirstChild(); node != null; node = node.getNextSibling()) if (node instanceof Element e) {
            require("version".equals(e.getLocalName()) && e.getNamespaceURI() == null && e.getElementsByTagName("*").getLength() == 0, "invalid version entry"); String value = e.getTextContent().strip(); require(!value.isEmpty() && seen.add(value), "empty or duplicate version entry"); count++;
            if (!value.startsWith(family + ".")) continue; if (value.matches(NUM + "\\." + NUM + "\\." + NUM + "\\.(?:Alpha|Beta|CR)[1-9][0-9]*")) continue;
            require(finals.putIfAbsent(version(value), value) == null, "ambiguous numerically equivalent versions");
        }
        require(count > 0 && seen.contains(pin) && pin.equals(finals.get(version(pin))), "declared version absent from metadata"); String greatest = finals.lastEntry().getValue(); return MonitorFiles.object().put("status", greatest.equals(pin) ? "current" : "newer_release").put("declared_version", pin).put("greatest_numeric_version", greatest).put("family", family).put("metadata_last_updated", timestamp);
    }
    static String javaBaseline(byte[] bytes) throws Exception {
        JsonNode pin = json(bytes); require(pin.isObject() && pin.size() == 1 && pin.path("version").isTextual() && pin.path("version").asText().matches("25(?:\\.[0-9]+){2}"), "unrecognized Java baseline"); return pin.path("version").asText();
    }
    static ObjectNode temurin(JsonNode items) throws Invalid {
        require(items.isArray() && items.size() == 1 && items.get(0).isObject(), "expected exactly one asset"); JsonNode asset = items.get(0), binary = asset.path("binary"), version = asset.path("version"); require(binary.isObject() && version.isObject() && asset.path("vendor").asText().equals("eclipse"), "missing binary or version");
        for (var e : Map.of("architecture", "x64", "os", "linux", "image_type", "jdk", "jvm_impl", "hotspot").entrySet()) require(binary.path(e.getKey()).asText().equals(e.getValue()), "asset does not match requested platform");
        String release = text(asset.get("release_name")), full = text(version.get("openjdk_version")); require(version.path("major").isIntegralNumber() && version.path("major").intValue() == 25 && release.matches("jdk-25(?:\\.[0-9]+){1,3}\\+[0-9]+") && full.matches("25(?:\\.[0-9]+){1,3}\\+[0-9]+(?:-[A-Za-z0-9.]+)?") && release.substring(4).equals(full.split("-", 2)[0]), "unrecognized or inconsistent release identity"); return MonitorFiles.object().put("status", "observed").put("release_name", release).put("openjdk_version", full);
    }
    static ObjectNode netty(Path path) throws Exception {
        Path local = path.toAbsolutePath().normalize(); require(Files.isRegularFile(local, LinkOption.NOFOLLOW_LINKS), "selected path is not a regular file");
        BasicFileAttributes before = Files.readAttributes(local, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); require(before.size() <= 512L * 1024 * 1024, "JAR exceeds size limit");
        var digest = MessageDigest.getInstance("SHA-256"); long total = 0; try (var channel = Files.newByteChannel(local, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)); var input = java.nio.channels.Channels.newInputStream(channel)) { byte[] buffer = new byte[1024 * 1024]; int n; while ((n = input.read(buffer)) != -1) { total += n; require(total <= 512L * 1024 * 1024, "JAR exceeds size limit"); digest.update(buffer, 0, n); } }
        var modules = new TreeMap<String, ObjectNode>(); var unsupported = new TreeSet<String>(); var seen = new HashSet<String>(); int count = 0, candidates = 0;
        try (var zip = new ZipFile(local.toFile())) {
            var entries = zip.entries(); while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement(); require(++count <= 100000, "too many JAR entries"); String name = entry.getName(), prefix = "META-INF/maven/io.netty/", suffix = "/pom.properties"; if (!name.startsWith(prefix) || !name.endsWith(suffix)) continue;
                require(++candidates <= 256 && seen.add(name), "too many or duplicate Netty metadata entries"); String artifact = name.substring(prefix.length(), name.length() - suffix.length()); require(artifact.matches("netty-[A-Za-z0-9][A-Za-z0-9._-]{0,127}"), "invalid metadata path"); require(entry.getSize() >= 0 && entry.getSize() <= 16384, "metadata exceeds size limit");
                byte[] raw; try (var input = zip.getInputStream(entry)) { raw = input.readNBytes(16385); } require(raw.length <= 16384, "metadata exceeds size limit");
                boolean unsupportedForm = false; for (byte b : raw) if (b < 0) unsupportedForm = true;
                if (unsupportedForm) { unsupported.add(name); continue; }
                var props = new HashMap<String, String>(); for (String line : new String(raw, StandardCharsets.US_ASCII).split("\\R")) {
                    line = line.strip(); if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) continue; int equals = line.indexOf('='); if (equals < 0) { unsupportedForm = true; continue; }
                    String key = line.substring(0, equals).strip(), value = line.substring(equals + 1).strip(); require(!key.isEmpty() && props.putIfAbsent(key, value) == null, "invalid or duplicate property");
                    if (!key.matches("[A-Za-z0-9._-]+") || key.contains("\\") || value.contains("\\")) unsupportedForm = true;
                }
                if (unsupportedForm) { unsupported.add(name); continue; }
                require("io.netty".equals(props.get("groupId")) && artifact.equals(props.get("artifactId")) && props.getOrDefault("version", "").matches("[A-Za-z0-9][A-Za-z0-9._+~:-]{0,127}"), "invalid or conflicting coordinate");
                modules.put(artifact, MonitorFiles.object().put("groupId", "io.netty").put("artifactId", artifact).put("version", props.get("version")).put("metadata_entry", name));
            }
        }
        BasicFileAttributes after = Files.readAttributes(local, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); require(total == before.size() && before.size() == after.size() && before.lastModifiedTime().equals(after.lastModifiedTime()) && Objects.equals(before.fileKey(), after.fileKey()) && Files.isRegularFile(local, LinkOption.NOFOLLOW_LINKS), "JAR changed during inspection");
        var out = MonitorFiles.object().put("artifact", path.toString()).put("sha256", HexFormat.of().formatHex(digest.digest())).put("metadata_status", modules.isEmpty() || !unsupported.isEmpty() ? "unknown" : "observed").put("scope", NETTY_SCOPE);
        var array = out.putArray("modules"); modules.values().forEach(array::add); var failures = out.putArray("unsupported_metadata_entries"); unsupported.forEach(failures::add); return out;
    }

    static boolean filename(String name) { return name != null && name.length() <= 512 && name.matches("pool/[A-Za-z0-9+._~/-]+") && name.endsWith(".deb") && Arrays.stream(name.split("/", -1)).noneMatch(s -> s.isEmpty() || s.equals(".") || s.equals("..")); }
    static boolean packageVersion(String value) { return value != null && value.matches("[0-9][A-Za-z0-9.+~:-]{0,127}"); }
    static boolean hash(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
    static Map<String, String> architectures() { var map = new LinkedHashMap<String, String>(); map.put("tor", "amd64"); map.put("tor-geoipdb", "all"); return map; }
    static Map<String, ObjectNode> torManifest(byte[] bytes) throws Exception {
        require(bytes.length <= 65536, "manifest exceeds byte limit"); JsonNode entries = json(bytes); require(entries.isArray() && entries.size() == 2, "expected exactly two package pins"); var result = new HashMap<String, ObjectNode>();
        for (JsonNode entry : entries) {
            require(entry.isObject() && entry.size() == 4 && entry.has("package") && entry.has("version") && entry.has("url") && entry.has("sha256"), "invalid manifest fields"); String name = text(entry.get("package")), version = text(entry.get("version")), hash = text(entry.get("sha256"));
            require(architectures().containsKey(name) && !result.containsKey(name), "unexpected or duplicate package pin"); require(packageVersion(version) && hash(hash), "invalid pinned version or SHA256"); String file = "pool/main/t/tor/" + name + "_" + version + "_" + architectures().get(name) + ".deb";
            require(filename(file) && entry.path("url").asText().equals(TOR_BASE + file), "pinned URL does not match package identity and fixed repository"); result.put(name, MonitorFiles.object().put("version", version).put("filename", file).put("sha256", hash));
        }
        return result;
    }
    static Map<String, ObjectNode> torIndex(byte[] bytes) throws Exception {
        require(bytes.length <= LIMIT, "index exceeds byte limit"); var stanzas = new ArrayList<Map<String, String>>(); Map<String, String> fields = new HashMap<>(); String previous = null; int size = 0; Set<String> required = Set.of("package", "version", "architecture", "filename", "sha256");
        for (String raw : utf8(bytes).split("\n", -1)) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw; require(raw.getBytes(StandardCharsets.UTF_8).length <= 16384, "index line exceeds byte limit"); require(line.chars().noneMatch(c -> (c < 32 && c != 9) || c == 127), "invalid control character in index");
            if (line.isEmpty()) { if (!fields.isEmpty()) { stanzas.add(fields); require(stanzas.size() <= 2048, "too many package stanzas"); } fields = new HashMap<>(); previous = null; size = 0; continue; }
            size += raw.getBytes(StandardCharsets.UTF_8).length + 1; require(size <= 256 * 1024, "index stanza exceeds byte limit");
            if (line.startsWith(" ") || line.startsWith("\t")) { require(previous != null && !required.contains(previous), "invalid index field continuation"); continue; }
            var matcher = Pattern.compile("([A-Za-z0-9][A-Za-z0-9-]*):[ \\t]*(.*)").matcher(line); require(matcher.matches(), "malformed index field"); String key = matcher.group(1).toLowerCase(Locale.ROOT); require(fields.putIfAbsent(key, matcher.group(2)) == null, "duplicate index field"); previous = key;
        }
        if (!fields.isEmpty()) stanzas.add(fields); require(!stanzas.isEmpty() && stanzas.size() <= 2048, "empty index or too many package stanzas"); var identities = new HashSet<List<String>>(); var selected = new HashMap<String, ObjectNode>();
        for (var stanza : stanzas) {
            require(stanza.keySet().containsAll(required), "missing required package field"); String name = stanza.get("package"), architecture = stanza.get("architecture"), version = stanza.get("version"), file = stanza.get("filename"), hash = stanza.get("sha256");
            require(name.matches("[a-z0-9][a-z0-9+.-]{0,127}") && Set.of("amd64", "all").contains(architecture) && packageVersion(version) && filename(file) && hash(hash), "invalid package identity, filename or SHA256"); require(identities.add(List.of(name, version, architecture)), "duplicate package stanza");
            if (architectures().containsKey(name)) { require(!selected.containsKey(name) && architectures().get(name).equals(architecture), "ambiguous package or unexpected architecture"); selected.put(name, MonitorFiles.object().put("version", version).put("filename", file).put("sha256", hash)); }
        }
        require(selected.keySet().equals(architectures().keySet()), "missing selected package stanza"); return selected;
    }
    static ObjectNode torBase(Path manifest, Instant now) {
        var out = MonitorFiles.object().put("schema_version", 1).put("checked_at", stamp(now)).put("status", "unknown").put("source_manifest", manifest.toString()).putNull("source_error").put("security_status", "not_assessed").put("scope", TOR_SCOPE);
        out.putObject("selection").put("distribution", "noble").put("component", "main").put("index_architecture", "amd64"); out.putObject("index").put("url", TOR).put("input", "https").putNull("sha256").putNull("error"); var packages = out.putObject("packages"); for (var e : architectures().entrySet()) { var p = packages.putObject(e.getKey()).put("architecture", e.getValue()).putNull("source").putNull("published"); var comparison = p.putObject("comparison"); for (String key : List.of("version", "filename", "sha256")) comparison.put(key, "unknown"); } return out;
    }
    static void torObserve(ObjectNode out, Path manifest, Fetcher get) {
        Map<String, ObjectNode> source = null, upstream = null;
        try { source = torManifest(read(manifest, 65536)); } catch (Exception e) { out.put("source_error", reason(e)); }
        var index = (ObjectNode) out.get("index");
        if (source == null) index.put("error", "not requested because source manifest is unknown");
        else { try { byte[] bytes = get.get(TOR, LIMIT).bytes; index.put("sha256", MonitorFiles.hash(bytes)); upstream = torIndex(bytes); } catch (Exception e) { index.put("error", reason(e)); } }
        for (String name : architectures().keySet()) {
            var p = (ObjectNode) out.path("packages").path(name); if (source != null) p.set("source", source.get(name)); if (upstream != null) p.set("published", upstream.get(name));
            if (source != null && upstream != null) for (String field : List.of("version", "filename", "sha256")) ((ObjectNode) p.get("comparison")).put(field, source.get(name).get(field).equals(upstream.get(name).get(field)) ? "match" : "different");
        }
        out.put("status", source != null && upstream != null ? "observed" : "unknown");
    }

    static String advisoryNext(String link, String repo) throws Invalid {
        String next = linkNext(link); if (next == null) return null; URI uri = githubUri(next); String numeric = repo.startsWith("netty") ? "1064563" : "139914932";
        require(Set.of("/repos/" + repo + "/security-advisories", "/repositories/" + numeric + "/security-advisories").contains(uri.getRawPath()), "unsafe pagination URL"); var q = query(uri);
        require(q.size() == 3 && "published".equals(q.get("state")) && "100".equals(q.get("per_page")) && (q.containsKey("before") ^ q.containsKey("after")), "unexpected pagination URL"); String cursor = q.getOrDefault("before", q.get("after")); require(cursor != null && cursor.matches("[A-Za-z0-9_+=/\\-]{1,1024}"), "unexpected pagination URL"); return next;
    }
    static JsonNode advisoryText(JsonNode value, boolean nullable, boolean empty) throws Invalid {
        require(value != null && ((nullable && value.isNull()) || (value.isTextual() && (empty || !value.textValue().isEmpty()) && value.textValue().length() <= 4096 && value.textValue().chars().noneMatch(c -> c < 32 || c == 127))), "invalid advisory field"); return value;
    }
    static ObjectNode advisory(JsonNode item, String repo) throws Invalid {
        require(item.isObject(), "invalid advisory entry"); String id = text(item.get("ghsa_id")); require(matches(id, GHSA), "invalid advisory ID"); String url = "https://github.com/" + repo + "/security/advisories/" + id;
        require(item.path("state").asText().equals("published") && item.path("html_url").asText().equals(url), "invalid advisory state or URL"); String modified = date(text(item.get("updated_at"))); require(item.has("cve_id"), "missing advisory CVE field"); JsonNode vulnerabilities = item.get("vulnerabilities"); require(vulnerabilities != null && vulnerabilities.isArray() && !vulnerabilities.isEmpty() && vulnerabilities.size() <= 1000, "invalid vulnerabilities");
        var out = MonitorFiles.object().put("ghsa_id", id).put("url", url).put("updated_at", modified); out.set("cve_id", advisoryText(item.get("cve_id"), true, false)); var packages = out.putArray("packages");
        for (JsonNode vulnerability : vulnerabilities) {
            require(vulnerability.isObject() && vulnerability.path("package").isObject() && vulnerability.has("vulnerable_version_range") && vulnerability.has("patched_versions"), "invalid vulnerability entry"); JsonNode pkg = vulnerability.get("package"), ecosystem = advisoryText(pkg.get("ecosystem"), false, repo.startsWith("netty"));
            var entry = packages.addObject(); entry.set("ecosystem", ecosystem); entry.put("ecosystem_status", ecosystem.textValue().isEmpty() ? "unknown" : "reported"); entry.set("name", advisoryText(pkg.get("name"), false, false)); entry.set("vulnerable_version_range", advisoryText(vulnerability.get("vulnerable_version_range"), true, true)); entry.set("patched_versions", advisoryText(vulnerability.get("patched_versions"), true, true));
        }
        return out;
    }
    static ArrayNode advisories(String repo, Fetcher get) throws Exception {
        require(Set.of("netty/netty", "quarkusio/quarkus").contains(repo), "unsupported advisory repository"); String url = "https://api.github.com/repos/" + repo + "/security-advisories?state=published&per_page=100"; var seen = new HashSet<String>(); var ids = new HashSet<String>(); var candidates = MonitorFiles.JSON.createArrayNode();
        for (int page = 0; page < 10; page++) {
            require(seen.add(url), "pagination loop"); Response response = get.get(url, LIMIT); require(response.bytes.length <= LIMIT, "response too large"); JsonNode items = json(response.bytes); require(items.isArray() && items.size() <= 100, "invalid advisory response");
            for (JsonNode item : items) { var candidate = advisory(item, repo); require(ids.add(candidate.path("ghsa_id").textValue()), "duplicate advisory ID"); candidates.add(candidate); }
            url = advisoryNext(response.link, repo); if (url == null) { require(items.size() < 100, "possibly incomplete advisory list"); return candidates; }
        }
        throw new Invalid("pagination limit reached");
    }

    /** A body subscriber enforces the byte bound before accumulating data; the future bounds the entire exchange. */
    static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final int limit; private final ByteArrayOutputStream bytes = new ByteArrayOutputStream(); private final CompletableFuture<byte[]> result = new CompletableFuture<>(); private Flow.Subscription subscription;
        BoundedBody(int limit) { this.limit = limit; }
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription s) { subscription = s; s.request(1); }
        public void onNext(List<ByteBuffer> buffers) {
            try { for (ByteBuffer buffer : buffers) { require(buffer.remaining() <= limit - bytes.size(), "response too large"); byte[] chunk = new byte[buffer.remaining()]; buffer.get(chunk); bytes.write(chunk); } subscription.request(1); }
            catch (Exception e) { subscription.cancel(); result.completeExceptionally(e); }
        }
        public void onError(Throwable error) { result.completeExceptionally(error); }
        public void onComplete() { result.complete(bytes.toByteArray()); }
    }
    static boolean official(String url) {
        if (Set.of(QUARKUS, TEMURIN, TOR, AGE).contains(url)) return true;
        try {
            URI uri = githubUri(url); String path = uri.getRawPath();
            if (path.equals("/repos/nymtech/nym/releases") || path.equals("/repos/PurpleI2P/i2pd/releases")) { var q = query(uri); String count = path.contains("nymtech") ? "100" : "10"; return (q.size() == 1 || q.size() == 2 && q.getOrDefault("page", "").matches("[1-9][0-9]?")) && count.equals(q.get("per_page")); }
            for (String repo : List.of("netty/netty", "quarkusio/quarkus")) {
                if (url.equals("https://api.github.com/repos/" + repo + "/security-advisories?state=published&per_page=100")) return true;
                if (path.equals("/repos/" + repo + "/security-advisories") || path.equals("/repositories/" + (repo.startsWith("netty") ? "1064563" : "139914932") + "/security-advisories")) { advisoryNext("<" + url + ">; rel=\"next\"", repo); return true; }
            }
        } catch (Exception ignored) { } return false;
    }
    static Response fetch(String url, int limit) throws Exception {
        require(official(url) && limit > 0 && limit <= LIMIT, "unsupported observation endpoint");
        try (var client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build()) {
            var builder = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15)).header("User-Agent", "stargate-java-release-observation/1").header("Accept-Encoding", "identity");
            if (url.startsWith("https://api.github.com/")) builder.header("Accept", "application/vnd.github+json").header("X-GitHub-Api-Version", "2022-11-28"); else builder.header("Accept", url.equals(TOR) ? "text/plain" : url.equals(QUARKUS) ? "application/xml" : "application/json");
            var future = client.sendAsync(builder.GET().build(), info -> new BoundedBody(limit));
            try {
                HttpResponse<byte[]> response = future.get(15, TimeUnit.SECONDS); int status = response.statusCode(); require(status == 200 && response.uri().toString().equals(url), status == 403 || status == 429 ? "HTTP " + status + " (access or rate limit)" : "unexpected HTTP response");
                var headers = response.headers(); var lengths = headers.allValues("Content-Length"); require(lengths.size() <= 1, "invalid response length"); if (!lengths.isEmpty()) require(lengths.getFirst().matches("[0-9]{1,12}") && Long.parseLong(lengths.getFirst()) == response.body().length && response.body().length <= limit, "invalid response length");
                var encodings = headers.allValues("Content-Encoding"); require(encodings.isEmpty() || encodings.size() == 1 && encodings.getFirst().equalsIgnoreCase("identity"), "unsupported HTTP content encoding"); var links = headers.allValues("Link"); require(links.size() <= 1, "ambiguous pagination header"); return new Response(response.body(), links.isEmpty() ? null : links.getFirst());
            } finally { future.cancel(true); }
        }
    }
}
