// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** A local CLI transport; tests inject a fake instead of contacting a daemon. */
interface DockerTransport {
    String call(long timeoutSeconds, String... arguments) throws Exception;
    default String call(String... arguments) throws Exception { return call(120, arguments); }
    default JsonNode inspect(String kind, String name) throws Exception {
        JsonNode value = DockerPolicy.parse(call(kind, "inspect", name));
        if (!value.isArray() || value.size() != 1 || !value.get(0).isObject()) throw DockerPolicy.failure();
        return value.get(0);
    }
    final class ProcessClient implements DockerTransport {
        private static final int LIMIT = 1024 * 1024;
        private final String executable;
        ProcessClient(String executable) { this.executable = executable; }
        public String call(long timeoutSeconds, String... arguments) throws Exception {
            if (timeoutSeconds <= 0 || timeoutSeconds > 1800) throw DockerPolicy.failure();
            List<String> command = new ArrayList<>(List.of(executable, "--host", "unix:///var/run/docker.sock"));
            command.addAll(List.of(arguments));
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.environment().remove("DOCKER_HOST"); builder.environment().remove("DOCKER_CONTEXT");
            builder.environment().remove("DOCKER_TLS_VERIFY"); builder.environment().remove("DOCKER_CERT_PATH");
            builder.environment().remove("DOCKER_API_VERSION");
            Process process = builder.start();
            var workers = Executors.newVirtualThreadPerTaskExecutor();
            {
                var stdout = workers.submit(() -> {try{return bounded(process.getInputStream());}catch(IOException e){process.destroyForcibly();throw e;}});
                var stderr = workers.submit(() -> {try{return bounded(process.getErrorStream());}catch(IOException e){process.destroyForcibly();throw e;}});
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
                boolean completed = false;
                try {
                    if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) throw new IOException("Docker outcome uncertain");
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0) throw new IOException("Docker outcome uncertain");
                    byte[] output = stdout.get(remaining, TimeUnit.NANOSECONDS);
                    remaining = deadline - System.nanoTime();
                    if (remaining <= 0) throw new IOException("Docker outcome uncertain");
                    byte[] errors = stderr.get(remaining, TimeUnit.NANOSECONDS);
                    if (process.exitValue() != 0 || errors.length > LIMIT) throw new IOException("Docker outcome uncertain");
                    try {
                        String result = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(output)).toString().strip();
                        completed = true; return result;
                    }
                    catch (CharacterCodingException e) { throw DockerPolicy.failure(); }
                } finally {
                    if (!completed) process.descendants().forEach(ProcessHandle::destroyForcibly);
                    if (process.isAlive()) { process.destroyForcibly(); process.waitFor(); }
                    stdout.cancel(true); stderr.cancel(true);
                    workers.shutdownNow();
                    if(completed){process.getInputStream().close();process.getErrorStream().close();process.getOutputStream().close();}
                }
            }
        }
        private static byte[] bounded(InputStream stream) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] block = new byte[8192]; int n;
            while ((n = stream.read(block)) != -1) {
                if (out.size() + n > LIMIT) throw new IOException("Docker output too large");
                out.write(block, 0, n);
            }
            return out.toByteArray();
        }
    }
}
