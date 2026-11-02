// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Java 25 source program: stage an issuer's RSA/EC PEM pair without restarting services. */
public final class SyncTlsCertificate {
    static final int LIMIT = 65536;
    static final Set<PosixFilePermission> PRIVATE = PosixFilePermissions.fromString("rw-------");
    static final Set<PosixFilePermission> DIRECTORY = PosixFilePermissions.fromString("rwxr-x---");
    interface Reader { byte[] read(Path path, boolean secret) throws Exception; }
    record Result(boolean changed, String certificateSha256) {
        String json() {
            return "{\"changed\":" + changed + ",\"certificateSha256\":\"" + certificateSha256
                    + "\",\"reload\":\"Proxy polls every 5 seconds; manager every 30 seconds. Existing connections retain their negotiated TLS session.\"}";
        }
    }

    static void require(boolean condition, String reason) throws IOException {
        if (!condition) throw new IOException(reason);
    }

    static byte[] snapshot(Path path, boolean secret) throws Exception {
        // Issuer symlinks are supported; snapshot the resolved regular file and
        // reject a concurrent replacement/write. Validation uses these same bytes.
        Path resolved = path.toRealPath();
        var before = Files.readAttributes(resolved, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Object ctime = Files.getAttribute(resolved, "unix:ctime", LinkOption.NOFOLLOW_LINKS);
        require(before.isRegularFile(), "TLS_SOURCE_NOT_REGULAR");
        if (secret) require(before.permissions().stream().noneMatch(p -> p.name().startsWith("GROUP_")
                || p.name().startsWith("OTHERS_")), "TLS_SOURCE_KEY_NOT_PRIVATE");
        byte[] bytes;
        try (var channel = FileChannel.open(resolved, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = java.nio.channels.Channels.newInputStream(channel).readNBytes(LIMIT + 1);
        }
        require(bytes.length <= LIMIT, "TLS_FILE_TOO_LARGE");
        var after = Files.readAttributes(resolved, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        require(Objects.equals(before.fileKey(), after.fileKey()) && before.size() == after.size()
                && before.lastModifiedTime().equals(after.lastModifiedTime())
                && before.permissions().equals(after.permissions())
                && Objects.equals(ctime, Files.getAttribute(resolved, "unix:ctime", LinkOption.NOFOLLOW_LINKS)),
                "TLS_SOURCE_CHANGED_DURING_READ");
        return bytes;
    }

    static byte[] pkcs8(byte[] key) throws Exception {
        var builder = new ProcessBuilder("/usr/bin/openssl", "pkcs8", "-topk8", "-nocrypt", "-passin", "pass:")
                .redirectError(ProcessBuilder.Redirect.DISCARD);
        builder.environment().clear();
        builder.environment().put("PATH", "/usr/bin:/bin");
        builder.environment().put("LANG", "C");
        Process process = builder.start();
        try (var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            var output = workers.submit(() -> process.getInputStream().readNBytes(LIMIT + 1));
            var input = workers.submit(() -> { try (var stream = process.getOutputStream()) { stream.write(key); } return true; });
            long until = System.nanoTime() + Duration.ofSeconds(20).toNanos();
            try {
                input.get(Math.max(1, until - System.nanoTime()), TimeUnit.NANOSECONDS);
                byte[] converted = output.get(Math.max(1, until - System.nanoTime()), TimeUnit.NANOSECONDS);
                require(converted.length <= LIMIT && process.waitFor(Math.max(1, until - System.nanoTime()), TimeUnit.NANOSECONDS)
                        && process.exitValue() == 0, "TLS_KEY_CONVERSION_FAILED");
                return converted;
            } finally {
                process.destroyForcibly();
                process.getInputStream().close();
                process.getOutputStream().close();
                input.cancel(true); output.cancel(true);
            }
        }
    }

    static byte[] validate(byte[] chain, byte[] sourceKey) throws Exception {
        var certificates = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(chain));
        require(!certificates.isEmpty(), "TLS_CHAIN_EMPTY");
        var leaf = (X509Certificate) certificates.iterator().next();
        leaf.checkValidity();
        String algorithm = leaf.getPublicKey().getAlgorithm();
        String signature = switch (algorithm) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new IOException("TLS_KEY_ALGORITHM_UNSUPPORTED");
        };
        byte[] privatePem = pkcs8(sourceKey);
        String pem = new String(privatePem, java.nio.charset.StandardCharsets.US_ASCII);
        require(pem.startsWith("-----BEGIN PRIVATE KEY-----"), "TLS_PKCS8_REQUIRED");
        byte[] der = Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", ""));
        var privateKey = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        byte[] challenge = MessageDigest.getInstance("SHA-256").digest(chain);
        var signer = Signature.getInstance(signature);
        signer.initSign(privateKey); signer.update(challenge); byte[] signed = signer.sign();
        signer.initVerify(leaf.getPublicKey()); signer.update(challenge);
        require(signer.verify(signed), "TLS_KEY_MISMATCH");
        return privatePem;
    }

    static int currentUid() throws IOException {
        return ((Number) Files.getAttribute(Path.of("/proc/" + ProcessHandle.current().pid()), "unix:uid")).intValue();
    }

    static void outputDirectory(Path output, int uid) throws Exception {
        require(output.isAbsolute() && output.equals(output.normalize()), "TLS_OUTPUT_PATH_INVALID");
        Path current = output.getRoot();
        for (Path part : output) {
            current = current.resolve(part);
            if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS))
                Files.createDirectory(current, PosixFilePermissions.asFileAttribute(DIRECTORY));
            var attributes = Files.readAttributes(current, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            require(attributes.isDirectory(), "TLS_OUTPUT_DIRECTORY_SYMLINK_OR_NOT_DIRECTORY");
            int mode = ((Number) Files.getAttribute(current, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
            int owner = ((Number) Files.getAttribute(current, "unix:uid", LinkOption.NOFOLLOW_LINKS)).intValue();
            require(owner == 0 || owner == currentUid() || (current.equals(output) && owner == uid),
                    "TLS_OUTPUT_DIRECTORY_OWNER_UNTRUSTED");
            require((mode & 0022) == 0 || (!current.equals(output) && owner == 0 && (mode & 01000) != 0),
                    "TLS_OUTPUT_DIRECTORY_WRITABLE");
        }
        // The application must not be able to rename the output directory itself.
        // Root-owned sticky /tmp may be an ancestor, but not its immediate parent.
        require((((Number) Files.getAttribute(output.getParent(), "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue() & 0022) == 0,
                "TLS_OUTPUT_PARENT_WRITABLE");
    }

    @SuppressWarnings("unchecked")
    static SecureDirectoryStream<Path> secure(DirectoryStream<Path> stream) throws IOException {
        require(stream instanceof SecureDirectoryStream<?>, "TLS_SECURE_DIRECTORY_OPERATIONS_REQUIRED");
        return (SecureDirectoryStream<Path>) stream;
    }

    static byte[] existing(SecureDirectoryStream<Path> directory, Path name) throws Exception {
        try {
            var attributes = directory.getFileAttributeView(name, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
            require(attributes.isRegularFile(), "TLS_DEPLOYMENT_NOT_REGULAR");
            try (var channel = directory.newByteChannel(name, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
                byte[] bytes = java.nio.channels.Channels.newInputStream(channel).readNBytes(LIMIT + 1);
                require(bytes.length <= LIMIT, "TLS_DEPLOYMENT_TOO_LARGE");
                return bytes;
            }
        } catch (NoSuchFileException missing) { return null; }
    }

    static void force(SeekableByteChannel channel) throws IOException {
        require(channel instanceof FileChannel, "TLS_DURABLE_FILE_CHANNEL_REQUIRED");
        ((FileChannel) channel).force(true);
    }

    static Result sync(Path certificate, Path key, Path output, int uid) throws Exception {
        return sync(certificate, key, output, uid, SyncTlsCertificate::snapshot);
    }

    static Result sync(Path certificate, Path key, Path output, int uid, Reader reader) throws Exception {
        require(uid >= 0, "TLS_UID_INVALID");
        byte[] chain = reader.read(certificate, false), sourceKey = reader.read(key, true);
        byte[] privatePem = validate(chain, sourceKey);
        outputDirectory(output, uid);
        var lookup = FileSystems.getDefault().getUserPrincipalLookupService();
        UserPrincipal owner = lookup.lookupPrincipalByName(Integer.toString(uid));
        GroupPrincipal group = lookup.lookupPrincipalByGroupName(Integer.toString(uid));
        var values = new LinkedHashMap<Path, byte[]>();
        values.put(Path.of("server.crt"), chain); values.put(Path.of("server.key"), privatePem);
        boolean changed = false, repair = false;
        try (var parent = Files.newDirectoryStream(output.getParent());
                var directory = secure(parent).newDirectoryStream(output.getFileName(), LinkOption.NOFOLLOW_LINKS)) {
            var opened = directory.getFileAttributeView(PosixFileAttributeView.class).readAttributes();
            require(opened.isDirectory() && (opened.owner().equals(owner)
                    || opened.owner().equals(lookup.lookupPrincipalByName(Integer.toString(currentUid())))
                    || opened.owner().equals(lookup.lookupPrincipalByName("0")))
                    && opened.permissions().stream().noneMatch(p -> p == PosixFilePermission.GROUP_WRITE || p == PosixFilePermission.OTHERS_WRITE),
                    "TLS_OUTPUT_DIRECTORY_CHANGED");
            for (var entry : values.entrySet()) {
                byte[] previous = existing(directory, entry.getKey());
                if (!Arrays.equals(previous, entry.getValue())) changed = true;
                if (previous != null) {
                    var attributes = directory.getFileAttributeView(entry.getKey(), PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
                    repair |= !attributes.owner().equals(owner) || !attributes.group().equals(group) || !attributes.permissions().equals(PRIVATE);
                }
            }
            if (changed || repair) {
                // A root-private staging directory keeps file metadata changes away
                // from the app-writable destination entries. Moves are fd-relative.
                Path stageName = Path.of(".tls-stage-" + UUID.randomUUID());
                Files.createDirectory(output.resolve(stageName), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                try (var stage = directory.newDirectoryStream(stageName, LinkOption.NOFOLLOW_LINKS)) {
                    var stageAttributes = stage.getFileAttributeView(PosixFileAttributeView.class).readAttributes();
                    require(stageAttributes.owner().equals(lookup.lookupPrincipalByName(Integer.toString(currentUid())))
                            && stageAttributes.permissions().equals(PosixFilePermissions.fromString("rwx------")),
                            "TLS_STAGING_DIRECTORY_UNTRUSTED");
                    try {
                        for (var entry : values.entrySet()) {
                            try (var file = stage.newByteChannel(entry.getKey(), Set.of(StandardOpenOption.WRITE,
                                    StandardOpenOption.CREATE_NEW, LinkOption.NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(PRIVATE))) {
                                var buffer = ByteBuffer.wrap(entry.getValue()); while (buffer.hasRemaining()) file.write(buffer);
                                var view = stage.getFileAttributeView(entry.getKey(), PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                                view.setOwner(owner); view.setGroup(group); view.setPermissions(PRIVATE); force(file);
                            }
                        }
                        // Both exact snapshots are valid before either rename.
                        // Existing JVM contexts survive the brief mixed-pair gap.
                        for (Path name : values.keySet()) stage.move(name, directory, name);
                    } finally {
                        for (Path name : values.keySet()) try { stage.deleteFile(name); } catch (NoSuchFileException ignored) { }
                    }
                } finally { directory.deleteDirectory(stageName); }
            }
            var view = directory.getFileAttributeView(PosixFileAttributeView.class);
            view.setOwner(owner); view.setGroup(group); view.setPermissions(DIRECTORY);
            try (var channel = FileChannel.open(output, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) { channel.force(true); }
        }
        return new Result(changed, HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(chain)));
    }

    public static void main(String[] args) {
        try {
            var values = new HashMap<String, String>();
            for (int i = 0; i < args.length; i += 2) {
                require(i + 1 < args.length && Set.of("--certificate", "--key", "--output", "--uid").contains(args[i])
                        && values.putIfAbsent(args[i], args[i + 1]) == null, "TLS_ARGUMENTS_INVALID");
            }
            for (String name : List.of("--certificate", "--key", "--output")) require(values.containsKey(name), "TLS_ARGUMENT_REQUIRED");
            System.out.println(sync(Path.of(values.get("--certificate")), Path.of(values.get("--key")),
                    Path.of(values.get("--output")), Integer.parseInt(values.getOrDefault("--uid", "10001"))).json());
        } catch (Exception error) {
            System.err.println("TLS_CERTIFICATE_SYNC_FAILED: check issuer files, validity, key match and permissions; success was not recorded.");
            System.exit(1);
        }
    }
}
