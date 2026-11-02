// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Server TLS only; destination TLS continues through CONNECT without interception. */
public final class RemoteTls implements AutoCloseable {
    public record Settings(int port, Path certificate, Path key) {
        public Settings {
            if (port < 1 || port > 65535 || certificate == null || key == null
                    || !certificate.isAbsolute() || !key.isAbsolute()) throw new IllegalArgumentException("INVALID_TLS_SETTINGS");
        }
    }
    private final Settings settings;
    private volatile SslContext context;
    private byte[] digest;
    private boolean failed;
    private final java.util.concurrent.ScheduledExecutorService refresh;

    RemoteTls(Settings settings) {
        this.settings = settings;
        try { reload(); } catch (Exception e) { throw new IllegalArgumentException("TLS_CONFIGURATION_INVALID", e); }
        refresh = Executors.newSingleThreadScheduledExecutor(task -> Thread.ofPlatform().daemon().name("tls-refresh").unstarted(task));
        refresh.scheduleWithFixedDelay(() -> {
            try {
                reload();
                if (failed) System.err.println("TLS_RELOAD_RECOVERED");
                failed = false;
            } catch (Exception e) {
                if (!failed) System.err.println("TLS_RELOAD_FAILED_PREVIOUS_CERTIFICATE_RETAINED");
                failed = true;
            }
        }, 5, 5, TimeUnit.SECONDS);
    }
    SslContext context() { return context; }
    synchronized void reload() throws Exception {
        byte[] cert = read(settings.certificate(), false), key = read(settings.key(), true);
        var hash = MessageDigest.getInstance("SHA-256");hash.update(cert);hash.update(key);byte[] next = hash.digest();
        if (MessageDigest.isEqual(digest == null ? new byte[0] : digest, next)) return;
        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(cert));
        leaf.checkValidity();
        String pem = new String(key, java.nio.charset.StandardCharsets.US_ASCII);
        if (!pem.startsWith("-----BEGIN PRIVATE KEY-----")) throw new IllegalArgumentException("TLS_KEY_REQUIRES_PKCS8");
        byte[] der = Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", ""));
        String algorithm = leaf.getPublicKey().getAlgorithm();
        String signature = switch (algorithm) { case "RSA" -> "SHA256withRSA"; case "EC" -> "SHA256withECDSA"; default -> throw new IllegalArgumentException("TLS_KEY_ALGORITHM_UNSUPPORTED"); };
        var privateKey = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        var signer = Signature.getInstance(signature);signer.initSign(privateKey);signer.update(next);byte[] signed = signer.sign();
        signer.initVerify(leaf.getPublicKey());signer.update(next);
        if (!signer.verify(signed)) throw new IllegalArgumentException("TLS_KEY_MISMATCH");
        SslContext replacement = SslContextBuilder.forServer(privateKey, certificates(cert)).sslProvider(SslProvider.JDK)
                .protocols("TLSv1.3", "TLSv1.2").build();
        context = replacement;digest = next;
    }
    private static X509Certificate[] certificates(byte[] bytes) throws Exception {
        return CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(bytes)).toArray(X509Certificate[]::new);
    }
    private static byte[] read(Path path, boolean secret) throws Exception {
        if (!Files.isRegularFile(path) || Files.size(path) > 65536) throw new IllegalArgumentException("INVALID_TLS_FILE");
        if (secret && Files.getPosixFilePermissions(path).stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_")))
            throw new IllegalArgumentException("TLS_KEY_MUST_BE_PRIVATE");
        return Files.readAllBytes(path);
    }
    @Override public void close() { refresh.shutdownNow(); }
}
