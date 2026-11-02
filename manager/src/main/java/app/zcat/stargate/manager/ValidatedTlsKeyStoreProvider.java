// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import io.quarkus.tls.KeyStoreAndKeyCertOptions;
import io.quarkus.tls.KeyStoreProvider;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.PemKeyCertOptions;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/** Validate each PEM snapshot before Quarkus can replace its working TLS context. */
@ApplicationScoped
public class ValidatedTlsKeyStoreProvider implements KeyStoreProvider {
    @Inject @ConfigProperty(name = "quarkus.http.ssl.certificate.files")
    Optional<String> certificateFile;
    @Inject @ConfigProperty(name = "quarkus.http.ssl.certificate.key-files")
    Optional<String> keyFile;
    private boolean failed;

    @Override public synchronized KeyStoreAndKeyCertOptions getKeyStore(Vertx vertx) {
        // The runtime enables the default TLS registry only for remote HTTPS.
        if (certificateFile.isEmpty() && keyFile.isEmpty()) return null;
        try {
            var result = load(vertx, singlePath(certificateFile), singlePath(keyFile));
            if (failed) System.err.println("MANAGER_TLS_CONFIGURATION_RECOVERED");
            failed = false;
            return result;
        } catch (Exception e) {
            if (!failed) System.err.println("MANAGER_TLS_CONFIGURATION_REJECTED");
            failed = true;
            // The registry catches supplier failure before replacing its options.
            throw new IllegalArgumentException("MANAGER_TLS_CONFIGURATION_INVALID");
        }
    }

    private static Path singlePath(Optional<String> value) {
        String path = value.orElseThrow();
        if (path.isBlank() || path.contains(",") || !Path.of(path).isAbsolute())
            throw new IllegalArgumentException("MANAGER_TLS_REQUIRES_ONE_ABSOLUTE_PEM_PAIR");
        return Path.of(path);
    }

    static KeyStoreAndKeyCertOptions load(Vertx vertx, Path certificate, Path key) throws Exception {
        byte[] cert = read(certificate, false), secret = read(key, true);
        var leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(cert));
        leaf.checkValidity();
        String pem = new String(secret, StandardCharsets.US_ASCII);
        if (!pem.startsWith("-----BEGIN PRIVATE KEY-----"))
            throw new IllegalArgumentException("TLS_KEY_REQUIRES_PKCS8");
        byte[] der = Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", ""));
        String algorithm = leaf.getPublicKey().getAlgorithm();
        String signature = switch (algorithm) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new IllegalArgumentException("TLS_KEY_ALGORITHM_UNSUPPORTED");
        };
        var privateKey = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        var hash = MessageDigest.getInstance("SHA-256");hash.update(cert);hash.update(secret);byte[] challenge = hash.digest();
        var signer = Signature.getInstance(signature);signer.initSign(privateKey);signer.update(challenge);byte[] signed = signer.sign();
        signer.initVerify(leaf.getPublicKey());signer.update(challenge);
        if (!signer.verify(signed)) throw new IllegalArgumentException("TLS_KEY_MISMATCH");
        // Feed exactly the validated bytes to Vert.x, without a second file read.
        var options = new PemKeyCertOptions().addCertValue(Buffer.buffer(cert)).addKeyValue(Buffer.buffer(secret));
        return new KeyStoreAndKeyCertOptions(options.loadKeyStore(vertx), options);
    }

    private static byte[] read(Path path, boolean secret) throws Exception {
        if (!Files.isRegularFile(path) || Files.size(path) > 65536) throw new IllegalArgumentException("INVALID_TLS_FILE");
        if (secret && Files.getPosixFilePermissions(path).stream()
                .anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_")))
            throw new IllegalArgumentException("TLS_KEY_MUST_BE_PRIVATE");
        return Files.readAllBytes(path);
    }
}
