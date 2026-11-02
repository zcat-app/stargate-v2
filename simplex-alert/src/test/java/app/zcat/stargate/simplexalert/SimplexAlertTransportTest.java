package app.zcat.stargate.simplexalert;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.*;

class SimplexAlertTransportTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration TIMEOUT = Duration.ofMillis(40);
    private static final URI ENDPOINT = URI.create("ws://127.0.0.1:5225/");

    @Test void encodesJsonSafelyAndRecognizesOnlyCorrelatedDirectAcceptance() throws Exception {
        String alert = "line\n\"quoted\" \\ /_send @2 json [] 😀";
        FakeSocket fake = new FakeSocket((socket, wire) -> {
            try {
                JsonNode envelope = JSON.readTree(wire);
                String cmd = envelope.path("cmd").asText();
                assertTrue(cmd.startsWith("/_send @5 json "));
                JsonNode messages = JSON.readTree(cmd.substring("/_send @5 json ".length()));
                assertEquals(1, messages.size());
                assertEquals(alert, messages.path(0).path("msgContent").path("text").asText());
                String corr = envelope.path("corrId").asText();
                socket.listener.onText(socket, ack("wrong", 5, 21), true);
                String ack = ack(corr, 5, 21);
                socket.listener.onText(socket, ack.substring(0, 20), false);
                socket.listener.onText(socket, ack.substring(20), true);
            } catch (Exception e) { throw new AssertionError(e); }
        });
        assertEquals(SimplexAlertTransport.Result.ACCEPTED, transport(fake).send(alert));
        assertTrue(fake.aborted);
    }

    @Test void explicitCorrelatedErrorIsRejectedWithoutSurfacingErrorContents() {
        FakeSocket fake = new FakeSocket((socket, wire) -> {
            String corr = correlation(wire);
            socket.listener.onText(socket, "{\"corrId\":\"" + corr + "\",\"resp\":{\"type\":\"chatCmdError\",\"chatError\":{\"type\":\"error\",\"errorType\":{\"type\":\"commandError\",\"message\":\"secret\"}}}}", true);
        });
        assertEquals(SimplexAlertTransport.Result.REJECTED, transport(fake).send("message"));
    }

    @Test void unrelatedMalformedOrMismatchedFramesNeverClaimAcceptance() {
        for (BiConsumer<FakeSocket, String> response : java.util.List.<BiConsumer<FakeSocket, String>>of(
                (s, w) -> s.listener.onText(s, "not json", true),
                (s, w) -> s.listener.onText(s, ack("unrelated", 5, 1), true),
                (s, w) -> s.listener.onText(s, ack(correlation(w), 6, 1), true),
                (s, w) -> s.listener.onText(s, ack(correlation(w), 5, 0), true),
                (s, w) -> s.listener.onText(s, "{\"corrId\":\"" + correlation(w) + "\",\"corrId\":\"" + correlation(w) + "\"}", true))) {
            assertEquals(SimplexAlertTransport.Result.UNKNOWN, transport(new FakeSocket(response)).send("message"));
        }
    }

    @Test void uncorrelatedErrorsAndResponsesWithoutCorrelationCannotResolveTheSend() {
        for (boolean absent : new boolean[]{false, true}) {
            FakeSocket fake = new FakeSocket((socket, wire) -> {
                String correlation = correlation(wire);
                String prefix = absent ? "" : "\"corrId\":\"unrelated\",";
                socket.listener.onText(socket, "{" + prefix + "\"resp\":{\"type\":\"chatCmdError\",\"chatError\":{\"type\":\"error\",\"errorType\":{\"type\":\"commandError\"}}}}", true);
                socket.listener.onText(socket, "{\"resp\":{\"type\":\"newChatItems\",\"chatItems\":[]}}", true);
                socket.listener.onText(socket, ack(correlation, 5, 21), true);
            });
            assertEquals(SimplexAlertTransport.Result.ACCEPTED, transport(fake).send("message"));
            assertEquals(1, fake.sends);
        }
    }

    @Test void absentOrUnrelatedErrorsAloneLeaveTheOutcomeUnknown() {
        for (String prefix : new String[]{"", "\"corrId\":\"unrelated\","}) {
            FakeSocket fake = new FakeSocket((socket, wire) -> socket.listener.onText(socket,
                    "{" + prefix + "\"resp\":{\"type\":\"chatCmdError\",\"chatError\":{\"type\":\"error\",\"errorType\":{\"type\":\"commandError\"}}}}", true));
            assertEquals(SimplexAlertTransport.Result.UNKNOWN, transport(fake).send("message"));
        }
    }

    @Test void timeoutAndConnectionLossAfterAttemptAreUnknownAndNoRetryOccurs() {
        FakeSocket lost = new FakeSocket((s, w) -> s.listener.onClose(s, 1006, "private"));
        assertEquals(SimplexAlertTransport.Result.UNKNOWN, transport(lost).send("alert"));
        assertEquals(1, lost.sends);
        FakeSocket silent = new FakeSocket((s, w) -> {});
        assertEquals(SimplexAlertTransport.Result.UNKNOWN, transport(silent).send("alert"));
        assertEquals(1, silent.sends);
        FakeSocket oversized = new FakeSocket((s, w) -> s.listener.onText(s, "x".repeat(1_048_577), false));
        assertEquals(SimplexAlertTransport.Result.UNKNOWN, transport(oversized).send("alert"));
        assertTrue(oversized.aborted);
    }

    @Test void failedAndLateConnectionAreNotSubmittedAndLateSocketIsAborted() {
        CompletableFuture<WebSocket> pending = new CompletableFuture<>();
        SimplexAlertTransport transport = new SimplexAlertTransport(ENDPOINT, "5", TIMEOUT, (u, l, t) -> pending);
        assertEquals(SimplexAlertTransport.Result.NOT_SUBMITTED, transport.send("alert"));
        FakeSocket late = new FakeSocket((s, w) -> {});
        pending.complete(late);
        assertTrue(late.aborted);
        assertEquals(0, late.sends);
    }

    @Test void rejectsUnsafeSelectorsEndpointsAndTextBeforeConnecting() {
        for (String id : new String[]{"", "0", "5 ", "5\n/_send", "-1", "1".repeat(20), "9223372036854775808"})
            assertThrows(IllegalArgumentException.class, () -> new SimplexAlertTransport(ENDPOINT, id, TIMEOUT));
        for (String uri : new String[]{"ws://localhost:5225", "ws://127.0.0.2:5225", "wss://127.0.0.1:5225", "ws://u:p@127.0.0.1:5225", "ws://127.0.0.1:5225/?q=x", "ws://127.0.0.1:5225/path"})
            assertThrows(IllegalArgumentException.class, () -> new SimplexAlertTransport(URI.create(uri), "5", TIMEOUT));
        assertDoesNotThrow(() -> new SimplexAlertTransport(URI.create("ws://[::1]:5225"), "5", TIMEOUT));
        FakeSocket fake = new FakeSocket((s, w) -> fail("must not connect"));
        SimplexAlertTransport t = transport(fake);
        for (String value : new String[]{"", "a".repeat(4001), "é".repeat(2001), "\ud800"})
            assertThrows(IllegalArgumentException.class, () -> t.send(value));
        assertEquals(0, fake.sends);
    }

    @Test void capturedInfoChatV7SendAcknowledgementIsAcceptedOnlyForItsCorrelationAndContact() throws Exception {
        String capture;
        try (var resource = getClass().getResourceAsStream("/infochat-v7-send-ack.json")) {
            assertNotNull(resource);
            capture = new String(resource.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        FakeSocket socket = new FakeSocket((s, w) -> {});
        var listener = new SimplexAlertTransport.Listener("c6", "3");
        listener.onText(socket, capture, true);
        assertEquals(SimplexAlertTransport.Result.ACCEPTED, listener.result.join());
        var other = new SimplexAlertTransport.Listener("other", "3");
        other.onText(socket, capture, true);
        assertFalse(other.result.isDone());
        var wrongContact = new SimplexAlertTransport.Listener("c6", "4");
        wrongContact.onText(socket, capture, true);
        assertEquals(SimplexAlertTransport.Result.UNKNOWN, wrongContact.result.join());
    }

    @Test void commandLineUsesBoundedInputAndReportsOnlyResult() {
        var bytes = new java.io.ByteArrayOutputStream();
        var output = new java.io.PrintStream(bytes, true, java.nio.charset.StandardCharsets.UTF_8);
        var input = new java.io.ByteArrayInputStream("secret alert".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        int result = SimplexAlertMain.run("ws://127.0.0.1:5225", "3", input, output, (endpoint, contact) -> text -> {
            assertEquals("secret alert", text);
            return SimplexAlertTransport.Result.ACCEPTED;
        });
        assertEquals(0, result);
        assertEquals("ACCEPTED\n", bytes.toString(java.nio.charset.StandardCharsets.UTF_8));
        bytes.reset();
        assertEquals(64, SimplexAlertMain.run("ws://127.0.0.1:5225", "3", new java.io.ByteArrayInputStream(new byte[4001]), output,
                (endpoint, contact) -> { throw new AssertionError("must not connect"); }));
        assertEquals("INVALID_INPUT\n", bytes.toString(java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test void commandLineOutputsOnlyFixedResultsAndDoesNotWriteStderr() {
        var prior = System.err;
        var stderrBytes = new java.io.ByteArrayOutputStream();
        try (var stderr = new java.io.PrintStream(stderrBytes, true, java.nio.charset.StandardCharsets.UTF_8)) {
            System.setErr(stderr);
            for (var expected : SimplexAlertTransport.Result.values()) {
                var stdoutBytes = new java.io.ByteArrayOutputStream();
                var stdout = new java.io.PrintStream(stdoutBytes, true, java.nio.charset.StandardCharsets.UTF_8);
                int code = SimplexAlertMain.run("ws://127.0.0.1:5225", "3",
                        new java.io.ByteArrayInputStream("sensitive message".getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                        stdout, (endpoint, contact) -> text -> expected);
                int expectedCode = switch (expected) {
                    case ACCEPTED -> 0;
                    case REJECTED -> 2;
                    case NOT_SUBMITTED -> 3;
                    case UNKNOWN -> 4;
                };
                assertEquals(expectedCode, code);
                assertEquals(expected.name() + "\n", stdoutBytes.toString(java.nio.charset.StandardCharsets.UTF_8));
            }
            var stdoutBytes = new java.io.ByteArrayOutputStream();
            var stdout = new java.io.PrintStream(stdoutBytes, true, java.nio.charset.StandardCharsets.UTF_8);
            assertEquals(4, SimplexAlertMain.run("ws://127.0.0.1:5225", "3",
                    new java.io.ByteArrayInputStream("sensitive message".getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                    stdout, (endpoint, contact) -> text -> { throw new IllegalStateException("private 3 sensitive message"); }));
            assertEquals("UNKNOWN\n", stdoutBytes.toString(java.nio.charset.StandardCharsets.UTF_8));
            assertEquals("", stderrBytes.toString(java.nio.charset.StandardCharsets.UTF_8));
        } finally {
            System.setErr(prior);
        }
    }

    private static SimplexAlertTransport transport(FakeSocket socket) {
        return new SimplexAlertTransport(ENDPOINT, "5", TIMEOUT, (u, listener, t) -> {
            socket.listener = listener; listener.onOpen(socket); return CompletableFuture.completedFuture(socket);
        });
    }
    private static String correlation(String wire) {
        try { return JSON.readTree(wire).path("corrId").asText(); }
        catch (Exception e) { throw new AssertionError(e); }
    }
    private static String ack(String correlation, int contact, int id) {
        return "{\"corrId\":\"" + correlation + "\",\"resp\":{\"type\":\"newChatItems\",\"chatItems\":[{\"chatInfo\":{\"type\":\"direct\",\"contact\":{\"contactId\":" + contact + "}},\"chatItem\":{\"chatDir\":{\"type\":\"directSnd\"},\"meta\":{\"itemId\":" + id + "}}}]}}";
    }
    private static final class FakeSocket implements WebSocket {
        final BiConsumer<FakeSocket, String> response;
        WebSocket.Listener listener;
        boolean aborted;
        int sends;
        FakeSocket(BiConsumer<FakeSocket, String> response) { this.response = response; }
        public CompletableFuture<WebSocket> sendText(CharSequence data, boolean last) { sends++; response.accept(this, data.toString()); return CompletableFuture.completedFuture(this); }
        public CompletableFuture<WebSocket> sendBinary(ByteBuffer data, boolean last) { throw new AssertionError(); }
        public CompletableFuture<WebSocket> sendPing(ByteBuffer data) { throw new AssertionError(); }
        public CompletableFuture<WebSocket> sendPong(ByteBuffer data) { throw new AssertionError(); }
        public CompletableFuture<WebSocket> sendClose(int status, String reason) { throw new AssertionError(); }
        public void request(long n) {}
        public String getSubprotocol() { return ""; }
        public boolean isOutputClosed() { return aborted; }
        public boolean isInputClosed() { return aborted; }
        public void abort() { aborted = true; }
    }
}
