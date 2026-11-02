// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.PemKeyCertOptions;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Signature;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.X509KeyManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ValidatedTlsKeyStoreProviderTest {
    @TempDir Path directory;

    private void generate(String name, String algorithm) throws Exception {
        var args = new java.util.ArrayList<>(java.util.List.of("openssl", "req", "-x509", "-newkey"));
        if (algorithm.equals("EC")) args.addAll(java.util.List.of("ec", "-pkeyopt", "ec_paramgen_curve:P-256"));
        else args.add("rsa:2048");
        args.addAll(java.util.List.of("-nodes", "-keyout", directory.resolve(name + ".key").toString(),
                "-out", directory.resolve(name + ".crt").toString(), "-days", "1", "-subj", "/CN=localhost"));
        var process = new ProcessBuilder(args).redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(process.waitFor(15, TimeUnit.SECONDS));assertEquals(0, process.exitValue());
        Files.setPosixFilePermissions(directory.resolve(name + ".key"), PosixFilePermissions.fromString("rw-------"));
    }

    private ValidatedTlsKeyStoreProvider provider() {
        var provider = new ValidatedTlsKeyStoreProvider();
        provider.certificateFile = Optional.of(directory.resolve("server.crt").toString());
        provider.keyFile = Optional.of(directory.resolve("server.key").toString());
        return provider;
    }

    private void deploy(String cert, String key) throws Exception {
        Files.copy(directory.resolve(cert + ".crt"), directory.resolve("server.crt"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(directory.resolve(key + ".key"), directory.resolve("server.key"), StandardCopyOption.REPLACE_EXISTING);
        Files.setPosixFilePermissions(directory.resolve("server.key"), PosixFilePermissions.fromString("rw-------"));
    }

    private void assertWorkingPair(io.quarkus.tls.KeyStoreAndKeyCertOptions pair, String algorithm) throws Exception {
        var factory = pair.options.getKeyManagerFactory(null);
        var manager = (X509KeyManager) factory.getKeyManagers()[0];
        String alias = manager.getServerAliases(algorithm, null)[0];
        var signer = Signature.getInstance(algorithm.equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA");
        signer.initSign(manager.getPrivateKey(alias));signer.update(new byte[]{1, 2, 3});byte[] signed = signer.sign();
        signer.initVerify(manager.getCertificateChain(alias)[0]);signer.update(new byte[]{1, 2, 3});
        assertTrue(signer.verify(signed), "published TLS options must contain a matching certificate and key");
    }

    @ParameterizedTest @ValueSource(strings = {"EC", "RSA"})
    void mismatchIsRejectedBeforePublicationAndMatchingRenewalRecovers(String algorithm) throws Exception {
        generate("first", algorithm);generate("second", algorithm);deploy("first", "first");
        var provider = provider();var first = provider.getKeyStore(null);assertWorkingPair(first, algorithm);
        deploy("first", "second");
        // Previously the loader accepted the pair and only client handshakes failed.
        var legacy = new PemKeyCertOptions().addCertValue(Buffer.buffer(Files.readAllBytes(directory.resolve("server.crt"))))
                .addKeyValue(Buffer.buffer(Files.readAllBytes(directory.resolve("server.key"))));
        assertNotNull(legacy.loadKeyStore(null));
        var error = assertThrows(IllegalArgumentException.class, () -> provider.getKeyStore(null));
        assertEquals("MANAGER_TLS_CONFIGURATION_INVALID", error.getMessage());
        // Existing options own immutable snapshots despite subsequent file changes.
        assertWorkingPair(first, algorithm);
        deploy("second", "second");var second = provider.getKeyStore(null);assertWorkingPair(second, algorithm);
        assertFalse(java.util.Arrays.equals(first.keyStore.getCertificate(first.keyStore.aliases().nextElement()).getEncoded(),
                second.keyStore.getCertificate(second.keyStore.aliases().nextElement()).getEncoded()));
    }

    @Test void malformedExpiredOrPublicKeyFileIsRejectedAndPreviousOptionsRemainUsable() throws Exception {
        generate("first", "EC");deploy("first", "first");var provider = provider();var first = provider.getKeyStore(null);
        Files.writeString(directory.resolve("server.crt"), "invalid certificate\n");
        assertThrows(IllegalArgumentException.class, () -> provider.getKeyStore(null));assertWorkingPair(first, "EC");
        deploy("first", "first");
        var process = new ProcessBuilder("openssl", "x509", "-in", directory.resolve("first.crt").toString(),
                "-signkey", directory.resolve("first.key").toString(), "-days", "-1", "-out", directory.resolve("server.crt").toString())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(process.waitFor(15, TimeUnit.SECONDS));assertEquals(0, process.exitValue());
        assertThrows(IllegalArgumentException.class, () -> provider.getKeyStore(null));assertWorkingPair(first, "EC");
        deploy("first", "first");Files.setPosixFilePermissions(directory.resolve("server.key"), PosixFilePermissions.fromString("rw-r-----"));
        assertThrows(IllegalArgumentException.class, () -> provider.getKeyStore(null));assertWorkingPair(first, "EC");
        deploy("first", "first");assertWorkingPair(provider.getKeyStore(null), "EC");
    }

    @Test void absentPemPairDoesNotEnableTlsAndIncompleteConfigurationFails() {
        var provider = new ValidatedTlsKeyStoreProvider();provider.certificateFile = Optional.empty();provider.keyFile = Optional.empty();
        assertNull(provider.getKeyStore(null));
        provider.certificateFile = Optional.of(directory.resolve("server.crt").toString());
        assertThrows(IllegalArgumentException.class, () -> provider.getKeyStore(null));
    }
}
