// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Set;

/** Reduce a bounded, explicitly published snapshot to display-safe values. */
final class ReleaseMonitor {
    record Observation(String latest, String attemptAt, String publishedAt, long limitSeconds) {}
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private ReleaseMonitor() {}

    static Observation read(Path path, long limit, Instant now) {
        return read(path, limit, now, () -> {});
    }

    // POSIX locks are process-wide; closing another descriptor for this inode can
    // release a lock. Serialize every reader from before open until after close.
    static synchronized Observation read(Path path, long limit, Instant now, Runnable afterLock) {
        var unknown = new Observation("unknown", null, null, limit);
        try {
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return unknown;
            byte[] bytes;
            try (var channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                // The publisher holds an exclusive POSIX record lock while updating this inode.
                try (var lock = channel.tryLock(0, Long.MAX_VALUE, true)) {
                    if (lock == null) return unknown;
                    afterLock.run();
                    bytes = Channels.newInputStream(channel).readNBytes(513);
                }
            }
            if (bytes.length > 512) return unknown;
            var node = JSON.readTree(bytes);
            if (node == null || !node.isObject() || node.size() != 4 || !node.has("schema_version") || !node.has("latest")
                    || !node.has("attempt_at") || !node.has("published_at") || !node.get("schema_version").isInt()
                    || node.get("schema_version").intValue() != 1 || !node.get("latest").isTextual()) return unknown;
            String latest = node.get("latest").textValue();
            if (!Set.of("observed", "pending", "unknown").contains(latest)) return unknown;
            Instant published = timestamp(node.get("published_at"));
            Instant attempt = node.get("attempt_at").isNull() ? null : timestamp(node.get("attempt_at"));
            if ((latest.equals("unknown")) != (attempt == null) || published.isAfter(now)
                    || Duration.between(published, now).compareTo(Duration.ofSeconds(limit)) > 0
                    || (attempt != null && (attempt.isAfter(published) || attempt.isAfter(now)
                    || Duration.between(attempt, now).compareTo(Duration.ofSeconds(limit)) > 0))) return unknown;
            return new Observation(latest, attempt == null ? null : DateTimeFormatter.ISO_INSTANT.format(attempt),
                    DateTimeFormatter.ISO_INSTANT.format(published), limit);
        } catch (Exception e) { return unknown; }
    }
    record ConsumerObservation(String outcome, String localAcceptance, Boolean futureCollectionBlocked,
                               String attemptAt, String publishedAt, long limitSeconds) {}

    // Use the same process-wide monitor as collection reads, including when both
    // settings accidentally name the same inode: a descriptor close releases POSIX locks.
    static synchronized ConsumerObservation readConsumer(Path path, long limit, Instant now) {
        var unknown = new ConsumerObservation("unknown", "unknown", null, null, null, limit);
        try {
            if (limit <= 0 || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return unknown;
            byte[] bytes;
            try (var channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                try (var lock = channel.tryLock(0, Long.MAX_VALUE, true)) {
                    if (lock == null) return unknown;
                    bytes = Channels.newInputStream(channel).readNBytes(513);
                }
            }
            if (bytes.length > 512) return unknown;
            var node = JSON.readTree(bytes);
            var fields = Set.of("schema_version", "published_at", "attempt_at", "outcome", "local_acceptance", "future_collection_blocked");
            if (node == null || !node.isObject() || node.size() != fields.size()
                    || !fields.stream().allMatch(node::has) || !node.get("schema_version").isInt()
                    || node.get("schema_version").intValue() != 1 || !node.get("outcome").isTextual()
                    || !node.get("local_acceptance").isTextual()) return unknown;
            String outcome = node.get("outcome").textValue(), acceptance = node.get("local_acceptance").textValue();
            var blocked = node.get("future_collection_blocked");
            boolean valid = switch (outcome) {
                case "quiet" -> acceptance.equals("not_attempted") && blocked.isBoolean() && !blocked.booleanValue();
                case "locally_accepted" -> acceptance.equals("accepted") && blocked.isBoolean() && !blocked.booleanValue();
                case "collection_unknown", "fresh_observation_required" -> Set.of("accepted", "not_attempted").contains(acceptance)
                        && blocked.isBoolean() && !blocked.booleanValue();
                case "blocked_pending", "blocked_uncertain" -> acceptance.equals("unknown") && blocked.isBoolean() && blocked.booleanValue();
                case "unknown", "busy", "incomplete" -> acceptance.equals("unknown") && blocked.isNull();
                default -> false;
            };
            if (!valid) return unknown;
            Instant published = timestamp(node.get("published_at"));
            Instant attempt = node.get("attempt_at").isNull() ? null : timestamp(node.get("attempt_at"));
            if (outcome.equals("unknown") || outcome.equals("incomplete") || attempt == null
                    || attempt.isAfter(published) || published.isAfter(now)
                    || Duration.between(published, now).compareTo(Duration.ofSeconds(limit)) > 0
                    || Duration.between(attempt, now).compareTo(Duration.ofSeconds(limit)) > 0) return unknown;
            return new ConsumerObservation(outcome, acceptance, blocked.isNull() ? null : blocked.booleanValue(),
                    DateTimeFormatter.ISO_INSTANT.format(attempt), DateTimeFormatter.ISO_INSTANT.format(published), limit);
        } catch (Exception e) { return unknown; }
    }

    private static Instant timestamp(com.fasterxml.jackson.databind.JsonNode node) {
        if (!node.isTextual() || !node.textValue().matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")) throw new IllegalArgumentException();
        Instant instant = Instant.parse(node.textValue());
        if (!DateTimeFormatter.ISO_INSTANT.format(instant).equals(node.textValue())) throw new IllegalArgumentException();
        return instant;
    }
}
