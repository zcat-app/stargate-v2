package app.zcat.stargate.simplexalert;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Outbound-only candidate for a separately operated simplex-chat v7.0.0 process. */
public final class SimplexAlertTransport {
    private static final int MAX_TEXT_BYTES = 4000;
    private static final int MAX_FRAME_CHARS = 1_048_576;
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    /** ACCEPTED means accepted locally by simplex-chat; recipient delivery is unknown. */
    public enum Result { ACCEPTED, REJECTED, NOT_SUBMITTED, UNKNOWN }

    @FunctionalInterface
    interface Connector {
        CompletableFuture<WebSocket> connect(URI endpoint, WebSocket.Listener listener, Duration timeout);
    }

    private final URI endpoint;
    private final String contactId;
    private final Duration timeout;
    private final Connector connector;

    public SimplexAlertTransport(URI endpoint, String contactId, Duration timeout) {
        this(endpoint, contactId, timeout, (uri, listener, duration) -> HttpClient.newBuilder()
                .proxy(ProxySelector.of(null)).connectTimeout(duration).build()
                .newWebSocketBuilder().connectTimeout(duration).buildAsync(uri, listener));
    }

    SimplexAlertTransport(URI endpoint, String contactId, Duration timeout, Connector connector) {
        this.endpoint = validateEndpoint(endpoint);
        if (contactId == null || !contactId.matches("[1-9][0-9]{0,18}")
                || new java.math.BigInteger(contactId).compareTo(java.math.BigInteger.valueOf(Long.MAX_VALUE)) > 0) {
            throw new IllegalArgumentException("Invalid contact selector");
        }
        if (timeout == null || timeout.isZero() || timeout.isNegative()
                || timeout.compareTo(Duration.ofMinutes(1)) > 0 || timeout.toMillis() == 0) {
            throw new IllegalArgumentException("Invalid timeout");
        }
        this.contactId = contactId;
        this.timeout = timeout;
        this.connector = Objects.requireNonNull(connector);
    }

    private static URI validateEndpoint(URI uri) {
        if (uri == null || !"ws".equals(uri.getScheme())
                || !("127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost()))
                || uri.getPort() < 1 || uri.getPort() > 65535
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || !(uri.getRawPath().isEmpty() || "/".equals(uri.getRawPath()))) {
            throw new IllegalArgumentException("Endpoint must be a literal loopback ws URI with a port");
        }
        return uri;
    }

    /** One in-flight alert per instance. Never retries; UNKNOWN may already have been sent. */
    public synchronized Result send(String text) {
        validateText(text);
        String correlation = UUID.randomUUID().toString();
        String command = encode(correlation, contactId, text);
        Listener listener = new Listener(correlation, contactId);
        WebSocket socket = null;
        CompletableFuture<WebSocket> opening = null;
        boolean attempted = false;
        try {
            opening = connector.connect(endpoint, listener, timeout);
            socket = opening.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (listener.result.isDone()) return Result.NOT_SUBMITTED;
            attempted = true; // From this point even a failed send can have reached the peer.
            socket.sendText(command, true).get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            return listener.result.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return attempted ? Result.UNKNOWN : Result.NOT_SUBMITTED;
        } catch (ExecutionException | TimeoutException | RuntimeException e) {
            return attempted ? Result.UNKNOWN : Result.NOT_SUBMITTED;
        } finally {
            if (socket != null) socket.abort();
            else if (opening != null) {
                // A handshake may complete after the caller times out. Close that socket too.
                opening.thenAccept(WebSocket::abort);
            }
        }
    }

    private static void validateText(String text) {
        if (text == null || text.isEmpty() || text.length() > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException("Invalid alert text");
        }
        try {
            ByteBuffer bytes = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(text));
            if (bytes.remaining() > MAX_TEXT_BYTES) throw new IllegalArgumentException("Invalid alert text");
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid alert text");
        }
    }

    private static String encode(String correlation, String contact, String text) {
        ObjectNode content = JSON.createObjectNode().put("type", "text").put("text", text);
        ObjectNode message = JSON.createObjectNode().set("msgContent", content);
        ArrayNode messages = JSON.createArrayNode().add(message);
        ObjectNode envelope = JSON.createObjectNode().put("corrId", correlation)
                .put("cmd", "/_send @" + contact + " json " + messages);
        return envelope.toString();
    }

    static final class Listener implements WebSocket.Listener {
        final CompletableFuture<Result> result = new CompletableFuture<>();
        private final String correlation;
        private final String contact;
        private final StringBuilder buffer = new StringBuilder();

        Listener(String correlation, String contact) { this.correlation = correlation; this.contact = contact; }
        @Override public void onOpen(WebSocket socket) { socket.request(1); }
        @Override public CompletionStage<?> onText(WebSocket socket, CharSequence data, boolean last) {
            if (data.length() > MAX_FRAME_CHARS - buffer.length()) {
                result.complete(Result.UNKNOWN);
                socket.abort();
                return CompletableFuture.completedFuture(null);
            }
            buffer.append(data);
            if (last) {
                process(buffer.toString());
                buffer.setLength(0);
            }
            socket.request(1);
            return CompletableFuture.completedFuture(null);
        }
        private void process(String frame) {
            try {
                JsonNode root = JSON.readTree(frame);
                if (root == null || !correlation.equals(root.path("corrId").textValue())) return;
                JsonNode resp = root.path("resp");
                JsonNode error = resp.path("chatError");
                boolean knownError = ("error".equals(error.path("type").textValue())
                        && error.path("errorType").path("type").isTextual())
                        || ("errorStore".equals(error.path("type").textValue())
                        && error.path("storeError").path("type").isTextual())
                        || ("errorAgent".equals(error.path("type").textValue())
                        && error.path("agentError").isObject());
                if ("chatCmdError".equals(resp.path("type").textValue()) && knownError) {
                    result.complete(Result.REJECTED);
                    return;
                }
                JsonNode items = resp.path("chatItems");
                JsonNode item = items.path(0);
                JsonNode id = item.path("chatItem").path("meta").path("itemId");
                JsonNode peer = item.path("chatInfo").path("contact").path("contactId");
                if ("newChatItems".equals(resp.path("type").textValue()) && items.isArray() && items.size() == 1
                        && "direct".equals(item.path("chatInfo").path("type").textValue())
                        && peer.isIntegralNumber() && contact.equals(peer.asText())
                        && "directSnd".equals(item.path("chatItem").path("chatDir").path("type").textValue())
                        && id.isIntegralNumber() && id.bigIntegerValue().signum() > 0) {
                    result.complete(Result.ACCEPTED);
                } else result.complete(Result.UNKNOWN);
            } catch (Exception ignored) {
                // Untrusted input is never logged; malformed frames cannot establish acceptance.
            }
        }
        @Override public CompletionStage<?> onBinary(WebSocket socket, ByteBuffer data, boolean last) {
            result.complete(Result.UNKNOWN); socket.abort(); return CompletableFuture.completedFuture(null);
        }
        @Override public CompletionStage<?> onClose(WebSocket socket, int statusCode, String reason) {
            result.complete(Result.UNKNOWN); return CompletableFuture.completedFuture(null);
        }
        @Override public void onError(WebSocket socket, Throwable error) { result.complete(Result.UNKNOWN); }
    }
}
