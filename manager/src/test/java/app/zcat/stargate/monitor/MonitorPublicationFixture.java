// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Supplies collection evidence to the real recorder, ledger, and snapshot publisher. */
public final class MonitorPublicationFixture {
    public static final String PRIVATE_TOKEN = "private-report-token-never-for-publication";
    private final MonitorMain.Config config;
    private final AtomicInteger sends = new AtomicInteger();
    private final String privateIdentity;

    public MonitorPublicationFixture(Path directory) throws Exception {
        Path recorder = createDirectory(directory.resolve("recorder"), "rwx------");
        Path ledger = createDirectory(directory.resolve("ledger"), "rwx------");
        Path dispatch = createDirectory(directory.resolve("dispatch"), "rwx------");
        Path output = createDirectory(directory.resolve("out"), "rwxr-xr-x");
        config = new MonitorMain.Config(directory, recorder, output, ledger, dispatch, directory.resolve("unused-profile"),
                "3", directory.resolve("unused.jar"), "3.40", "25.0.5+8", "v1.3.2",
                directory.resolve("unused-selection"), directory.resolve("unused-containers"), null, 900, 129600);
        var state = MonitorLedger.initial(config.ledgerMaxAge(), MonitorMain.now().minusSeconds(2));
        privateIdentity = state.path("epoch").asText();
        MonitorFiles.create(ledger.resolve("state.json"), MonitorFiles.bytes(state));
    }

    private static Path createDirectory(Path directory, String permissions) throws Exception {
        return Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(permissions)));
    }

    public Path snapshot() { return config.output().resolve("snapshot.json"); }
    public Path consumerSnapshot() { return config.output().resolve("consumer-snapshot.json"); }
    public String privateIdentity() { return privateIdentity; }
    public int sends() { return sends.get(); }
    public Path recordedReport() { return config.recorder().resolve("latest-report.json"); }

    @FunctionalInterface
    public interface DuringCollection { void run() throws Exception; }

    public int run(boolean changed, DuringCollection duringCollection) throws Exception {
        return MonitorMain.run(config, c -> {
            // MonitorMain has already published pending before entering collection.
            duringCollection.run();
            Instant checked = MonitorMain.now().minusSeconds(changed ? 0 : 1);
            var releases = releases(checked, changed);
            var runtime = runtime(checked);
            MonitorFiles.replace(c.recorder().resolve("latest-report.json"), releases);
            MonitorFiles.replace(c.recorder().resolve("latest-security-binding.json"), runtime);
            return List.of(releases, runtime);
        }, body -> { sends.incrementAndGet(); return "ACCEPTED"; });
    }

    private static ObjectNode releases(Instant checked, boolean changed) {
        var report = MonitorFiles.object().put("schema_version", 1).put("outcome", "observed")
                .put("completed_at", checked.toString()).put("private_token", PRIVATE_TOKEN);
        var checks = report.putObject("checks");
        for (String name : MonitorLedger.NAMES.subList(0, 7)) {
            var observation = checks.putObject(name).put("outcome", "observed").putObject("observation");
            observation.put("checked_at", checked.toString()).put("observed_at_utc", checked.toString())
                    .put("latest_tag", changed && name.equals("nym") ? "v2.0.0" : "v1.0.0")
                    .put("latest_published_at", checked.minusSeconds(60).toString()).put("family", "3.40")
                    .put("greatest_numeric_version", "3.40.1.1").put("metadata_last_updated", checked.minusSeconds(60).toString())
                    .put("selected_tag", "v1.0.0").put("sha256", "a".repeat(64));
            observation.putObject("upstream").put("release_name", "jdk-25.0.5+8").put("openjdk_version", "25.0.5+8");
            observation.putArray("modules");
            observation.putObject("packages").putObject("tor").putObject("published").put("version", "0.4.9.14");
        }
        for (String name : List.of("advisories", "quarkus_advisories")) {
            checks.putObject(name).put("outcome", "observed").putObject("observation")
                    .put("status", "observed").put("security_status", "not_assessed")
                    .put("checked_at", checked.toString()).putArray("candidates");
        }
        return report;
    }

    private static ObjectNode runtime(Instant checked) {
        var report = MonitorFiles.object().put("security_status", "not_assessed");
        report.putObject("deployment_binding").put("status", "observed").put("checked_at", checked.toString());
        var image = report.putObject("images").putObject("app").put("image_id", "sha256:" + "a".repeat(64));
        image.putObject("scan").putObject("source_binding").put("selected_image_id", "sha256:" + "a".repeat(64))
                .put("trivy_json_sha256", "b".repeat(64));
        var query = report.putObject("osv_observation").put("status", "observed").put("checked_at", checked.toString())
                .putArray("queries").addObject().put("ecosystem", "Maven").put("name", "io.netty:netty-common")
                .put("version", "4.1.135.Final");
        query.putArray("selected_records").addObject().put("role", "app").put("image_id", "sha256:" + "a".repeat(64))
                .put("evidence", "extracted_jar");
        query.putArray("candidates");
        return report;
    }
}
