// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;

import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static app.zcat.stargate.updater.UpdateFiles.require;

/** Bounded public downloads; transport never grants release authority. */
final class UpdateDownload {
    static final Duration TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_REDIRECTS = 5;
    private static final Set<Integer> REDIRECTS = Set.of(301, 302, 303, 307, 308);
    private UpdateDownload() {}

    static URI https(URI uri) {
        require(!uri.isOpaque() && "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null
                && uri.getRawUserInfo() == null && uri.getRawFragment() == null
                && (uri.getPort() == -1 || uri.getPort() > 0 && uri.getPort() <= 65535), "HTTPS_REQUIRED");
        return uri.normalize();
    }
    private static int port(URI uri) { return uri.getPort() == -1 ? 443 : uri.getPort(); }
    static boolean sameOrigin(URI first, URI second) {
        return first.getHost().equalsIgnoreCase(second.getHost()) && port(first) == port(second);
    }
    static URI redirect(URI previous, List<String> locations) {
        require(locations.size() == 1 && !locations.getFirst().isBlank(), "DOWNLOAD_REDIRECT_LOCATION_INVALID");
        URI next;
        try { next = https(previous.resolve(URI.create(locations.getFirst()))); }
        catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("DOWNLOAD_REDIRECT_LOCATION_INVALID"); }
        require(sameOrigin(previous, next) || githubAssetHop(previous, next), "DOWNLOAD_REDIRECT_ORIGIN_REJECTED");
        return next;
    }
    private static boolean githubAssetHop(URI previous, URI next) {
        return previous.getHost().equalsIgnoreCase("github.com") && port(previous) == 443
                && previous.getRawPath().matches("/[^/]+/[^/]+/releases/download/[^/]+/[^/]+")
                && next.getHost().equalsIgnoreCase("release-assets.githubusercontent.com") && port(next) == 443
                && next.getRawPath().matches("/github-production-release-asset/[0-9]+/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    }
    private static String visited(URI uri) {
        return uri.getHost().toLowerCase(Locale.ROOT) + ":" + port(uri)
                + (uri.getRawPath().isEmpty() ? "/" : uri.getRawPath())
                + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
    }
    static void https(URI source, Path output, long limit, boolean exact, HttpClient client, Duration budget) throws Exception {
        require(client.followRedirects() == HttpClient.Redirect.NEVER, "AUTOMATIC_REDIRECTS_REJECTED");
        try (var deadline = new Deadline(budget, client)) {
            URI current = https(source);
            var seen = new HashSet<String>();
            for (int hops = 0; ; hops++) {
                require(seen.add(visited(current)), "DOWNLOAD_REDIRECT_LOOP");
                var request = HttpRequest.newBuilder(current).timeout(deadline.remaining()).GET().build();
                HttpResponse<InputStream> response;
                try { response = client.send(request, HttpResponse.BodyHandlers.ofInputStream()); }
                catch (Exception failure) { deadline.check(); throw failure; }
                InputStream body = response.body(); deadline.input.set(body);
                try (body) {
                    deadline.check();
                    if (response.statusCode() == 200) { copy(body, output, limit, exact, deadline); return; }
                    require(REDIRECTS.contains(response.statusCode()), "DOWNLOAD_HTTP_ERROR");
                    require(hops < MAX_REDIRECTS, "DOWNLOAD_REDIRECT_LIMIT");
                    current = redirect(current, response.headers().allValues("Location"));
                } finally { deadline.input.compareAndSet(body, null); }
            }
        }
    }
    static void local(InputStream input, Path output, long limit, boolean exact) throws Exception {
        try (input; var deadline = new Deadline(TIMEOUT, null)) {
            deadline.input.set(input); copy(input, output, limit, exact, deadline);
        }
    }
    private static void copy(InputStream input, Path output, long limit, boolean exact, Deadline deadline) throws Exception {
        boolean created = false;
        try {
            try (var target = Files.newOutputStream(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                created = true;
                long count = 0; byte[] buffer = new byte[65536]; int read;
                while ((read = input.read(buffer)) != -1) {
                    deadline.check(); count = Math.addExact(count, read);
                    require(count <= limit, "DOWNLOAD_TOO_LARGE"); target.write(buffer, 0, read);
                }
                deadline.check(); require(!exact || count == limit, "DOWNLOAD_SIZE_MISMATCH");
            }
        } catch (Exception failure) {
            if (created) Files.deleteIfExists(output);
            deadline.check(); throw failure;
        }
    }
    private static final class Deadline implements AutoCloseable {
        final AtomicReference<InputStream> input = new AtomicReference<>();
        final AtomicBoolean expired = new AtomicBoolean();
        final long end;
        final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
        Deadline(Duration budget, HttpClient client) {
            require(!budget.isNegative() && !budget.isZero() && budget.compareTo(TIMEOUT) <= 0, "INVALID_DOWNLOAD_TIMEOUT");
            end = System.nanoTime() + budget.toNanos();
            timer.schedule(() -> {
                expired.set(true);
                if (client != null) client.shutdownNow();
                InputStream active = input.get();
                if (active != null) try { active.close(); } catch (IOException ignored) {}
            }, budget.toNanos(), TimeUnit.NANOSECONDS);
        }
        Duration remaining() throws IOException { check(); return Duration.ofNanos(Math.max(1, end - System.nanoTime())); }
        void check() throws IOException {
            if (expired.get() || end - System.nanoTime() <= 0) throw new IOException("DOWNLOAD_TIMED_OUT");
        }
        @Override public void close() { timer.shutdownNow(); }
    }
}
