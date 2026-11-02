package app.zcat.stargate.simplexalert;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** Single-shot alert entry point; reads the alert from standard input. */
public final class SimplexAlertMain {
    private SimplexAlertMain() {}
    @FunctionalInterface interface Sender { SimplexAlertTransport.Result send(String text); }
    @FunctionalInterface interface SenderFactory { Sender create(URI uri, String contact); }

    public static void main(String[] args) {
        int exit = run(System.getenv("SIMPLEX_ALERT_ENDPOINT"), System.getenv("SIMPLEX_ALERT_CONTACT_ID"),
                System.in, System.out, (uri, contact) -> new SimplexAlertTransport(uri, contact, Duration.ofSeconds(10))::send);
        if (exit != 0) System.exit(exit);
    }

    static int run(String endpoint, String contact, InputStream input, PrintStream output, SenderFactory factory) {
        try {
            if (endpoint == null || contact == null) throw new IllegalArgumentException();
            byte[] bytes = input.readNBytes(4001);
            if (bytes.length == 0 || bytes.length > 4000) throw new IllegalArgumentException();
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            Sender sender = factory.create(URI.create(endpoint), contact);
            SimplexAlertTransport.Result result;
            try {
                result = sender.send(text);
            } catch (RuntimeException e) {
                // The sender may have reached the service before failing.
                result = SimplexAlertTransport.Result.UNKNOWN;
            }
            output.println(result.name());
            return switch (result) {
                case ACCEPTED -> 0;
                case REJECTED -> 2;
                case NOT_SUBMITTED -> 3;
                case UNKNOWN -> 4;
            };
        } catch (CharacterCodingException e) {
            output.println("INVALID_INPUT");
            return 64;
        } catch (IOException | RuntimeException e) {
            output.println("INVALID_INPUT");
            return 64;
        }
    }
}
