// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import static org.junit.jupiter.api.Assertions.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RemoteTlsTest {
    @TempDir Path directory;
    private void generate(String prefix) throws Exception { generate(prefix,"rsa:2048"); }
    private void generate(String prefix, String algorithm) throws Exception {
        var process = new ProcessBuilder("openssl","req","-x509","-newkey",algorithm,"-nodes","-keyout",directory.resolve(prefix+".key").toString(),
                "-out",directory.resolve(prefix+".crt").toString(),"-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1")
                .redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(process.waitFor(15,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,process.exitValue());
        Files.setPosixFilePermissions(directory.resolve(prefix+".key"),java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
    }
    private int port() throws Exception { try(var socket=new ServerSocket(0)){return socket.getLocalPort();} }
    private RemoteTls.Settings settings(int port) { return new RemoteTls.Settings(port,directory.resolve("server.crt"),directory.resolve("server.key")); }
    private SSLContext trust(String prefix) throws Exception {
        var store=java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());store.load(null,null);
        try(var stream=Files.newInputStream(directory.resolve(prefix+".crt"))){store.setCertificateEntry("fixture",java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(stream));}
        var tm=javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());tm.init(store);
        var context=SSLContext.getInstance("TLS");context.init(null,tm.getTrustManagers(),null);return context;
    }
    @Test void typicalEcdsaCertificateIsSupported() throws Exception {
        var process=new ProcessBuilder("openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes",
                "-keyout",directory.resolve("server.key").toString(),"-out",directory.resolve("server.crt").toString(),"-days","1","-subj","/CN=localhost")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(process.waitFor(15,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,process.exitValue());
        Files.setPosixFilePermissions(directory.resolve("server.key"),java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        try(var tls=new RemoteTls(settings(1))){assertNotNull(tls.context());}
    }
    @Test void invalidReloadKeepsWorkingCertificateAndMatchingReplacementLoads() throws Exception {
        generate("server");generate("replacement");
        try(var tls=new RemoteTls(settings(1))) {
            var initial=tls.context();Files.copy(directory.resolve("replacement.key"),directory.resolve("server.key"),java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            assertThrows(Exception.class,tls::reload);assertSame(initial,tls.context());
            Files.copy(directory.resolve("replacement.crt"),directory.resolve("server.crt"),java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            tls.reload();assertNotSame(initial,tls.context());
        }
        Files.setPosixFilePermissions(directory.resolve("server.key"),java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
        assertThrows(IllegalArgumentException.class,()->new RemoteTls(settings(1)));
    }
    @Test void tlsListenerRejectsPlaintextAndUntrustedClientsAndRequiresProxyCredentials() throws Exception {
        generate("server");int tlsPort=port();
        var config=new ProxyConfig(new InetSocketAddress("127.0.0.1",0),new InetSocketAddress("127.0.0.1",9050),Map.of(),4,2000,1000,false,null,null,2000,null,2000,null,60,settings(tlsPort));
        try(var proxy=new ProxyServer(config).start()) {
            try(var plain=new Socket("127.0.0.1",tlsPort)) {
                plain.setSoTimeout(3000);plain.getOutputStream().write("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes());
                assertEquals(-1,plain.getInputStream().read());
            }
            try(var untrusted=(SSLSocket)SSLContext.getDefault().getSocketFactory().createSocket("127.0.0.1",tlsPort)) {
                assertThrows(javax.net.ssl.SSLHandshakeException.class,untrusted::startHandshake);
            }
            try(var client=(SSLSocket)trust("server").getSocketFactory().createSocket("localhost",tlsPort)) {
                var params=client.getSSLParameters();params.setEndpointIdentificationAlgorithm("HTTPS");client.setSSLParameters(params);client.setSoTimeout(3000);client.startHandshake();
                client.getOutputStream().write(("GET http://"+"a".repeat(56)+".onion/ HTTP/1.1\r\nHost: "+"a".repeat(56)+".onion\r\n\r\n").getBytes());
                assertTrue(new String(client.getInputStream().readAllBytes()).startsWith("HTTP/1.1 407"));
            }
        }
    }
    private static void awaitConnectionSlotReleased(ProxyServer proxy) throws Exception {
        // TLS close_notify can reach the client before the server's close-future listener runs.
        var field=ProxyServer.class.getDeclaredField("admission");field.setAccessible(true);
        var accepted=((Admission)field.get(proxy)).occupancy;
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
        while(accepted.get()!=0 && System.nanoTime()<until) Thread.sleep(5);
        assertEquals(0,accepted.get(),"connection slot was not released");
    }

    @Test void connectionSlotHelperReadsAdmissionOccupancy() throws Exception {
        var config=new ProxyConfig(new InetSocketAddress("127.0.0.1",0),new InetSocketAddress("127.0.0.1",9050),Map.of(),1,2000,1000);
        try(var proxy=new ProxyServer(config)) {
            var channel=new io.netty.channel.embedded.EmbeddedChannel();
            proxy.initializeConnection(channel,false);
            assertThrows(AssertionError.class, () -> awaitConnectionSlotReleased(proxy));
            channel.close();channel.runPendingTasks();
            awaitConnectionSlotReleased(proxy);
            channel.finishAndReleaseAll();
        }
    }

    @Test void incompleteTrickledHeadersExpireOnBothListenersAndCapacityRecovers() throws Exception {
        generate("server");int tlsPort=port();
        var config=new ProxyConfig(new InetSocketAddress("127.0.0.1",0),new InetSocketAddress("127.0.0.1",9050),Map.of(),1,2000,600,false,null,null,2000,null,2000,null,60,settings(tlsPort));
        var context=trust("server");
        try(var proxy=new ProxyServer(config).start()) {
            for (boolean tls : new boolean[]{false,true}) {
                try(Socket client=tls ? context.getSocketFactory().createSocket("localhost",tlsPort) : new Socket("127.0.0.1",proxy.port())) {
                    if (tls) ((SSLSocket)client).startHandshake();
                    client.setSoTimeout(80);
                    client.getOutputStream().write("GET http://test.onion/ HTTP/1.1\r\nHost: test.onion\r\nX-Test: ".getBytes(StandardCharsets.US_ASCII));
                    long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
                    boolean closed=false;
                    while(System.nanoTime()<until) {
                        try {
                            client.getOutputStream().write('x');client.getOutputStream().flush();
                            if(client.getInputStream().read()==-1) { closed=true;break; }
                            fail("unexpected response to incomplete headers");
                        } catch(SocketTimeoutException expected) { /* Continue sending within the inactivity window. */ }
                    }
                    assertTrue(closed,"trickled headers must expire on " + (tls ? "TLS" : "plain") + " listener");
                }
                awaitConnectionSlotReleased(proxy);
                try(Socket normal=tls ? context.getSocketFactory().createSocket("localhost",tlsPort) : new Socket("127.0.0.1",proxy.port())) {
                    normal.setSoTimeout(3000);
                    normal.getOutputStream().write("GET http://test.onion/ HTTP/1.1\r\nHost: test.onion\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    assertTrue(new String(normal.getInputStream().readAllBytes(),StandardCharsets.US_ASCII).startsWith("HTTP/1.1 407"));
                }
                awaitConnectionSlotReleased(proxy);
            }
        }
    }

    @Test void tlsHandshakeAndHeadersHaveSeparateTimeBudgets() throws Exception {
        generate("server");int tlsPort=port();
        var config=new ProxyConfig(new InetSocketAddress("127.0.0.1",0),new InetSocketAddress("127.0.0.1",9050),Map.of(),4,2000,1000,false,null,null,2000,null,2000,null,60,settings(tlsPort));
        try(var proxy=new ProxyServer(config).start();var raw=new Socket("127.0.0.1",tlsPort)) {
            Thread.sleep(550);
            try(var client=(SSLSocket)trust("server").getSocketFactory().createSocket(raw,"localhost",tlsPort,true)) {
                client.setSoTimeout(3000);client.startHandshake();
                Thread.sleep(550);
                client.getOutputStream().write("GET http://test.onion/ HTTP/1.1\r\nHost: test.onion\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                assertTrue(new String(client.getInputStream().readAllBytes(),StandardCharsets.US_ASCII).startsWith("HTTP/1.1 407"));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"TLSv1.2", "TLSv1.3"})
    void orderlyTlsCloseReleasesTunnelAndSlotWhileOtherDeviceStaysConnected(String protocol) throws Exception {
        generate("server");int tlsPort=port();
        String token="synthetic-tls-close-token-for-unit-tests";
        var hmac=new HmacPartition(new byte[32]);
        byte[] digest=ProxyConfig.digest(token.getBytes(StandardCharsets.US_ASCII));
        var profiles=Map.of("closing",new ProxyConfig.Profile(digest,hmac.forProfile("closing")),
                "survivor",new ProxyConfig.Profile(digest,hmac.forProfile("survivor")));
        try(var tor=new ProxyServerTest.FakeTor(ProxyServerTest.Mode.ECHO)) {
            var config=new ProxyConfig(new InetSocketAddress("127.0.0.1",0),
                    new InetSocketAddress("127.0.0.1",tor.listener.getLocalPort()),profiles,2,2000,1000,
                    false,null,null,2000,null,2000,null,60,settings(tlsPort));
            var context=io.netty.handler.ssl.SslContextBuilder.forClient()
                    .sslProvider(io.netty.handler.ssl.SslProvider.JDK)
                    .trustManager(directory.resolve("server.crt").toFile()).protocols(protocol).build();
            var group=new io.netty.channel.nio.NioEventLoopGroup(1);
            try(var proxy=new ProxyServer(config).start();
                    var survivor=new TlsTunnel(group,context,tlsPort,"survivor",token);
                    var closing=new TlsTunnel(group,context,tlsPort,"closing",token)) {
                assertEquals(protocol,closing.ssl.engine().getSession().getProtocol());
                survivor.echo("before-close");closing.echo("closing-device");
                // Send a real TLS close_notify, leaving TCP open until the proxy closes it.
                // Closing/aborting this client here would hide the leaked tunnel and admission slot.
                assertTrue(closing.ssl.closeOutbound().await(2,TimeUnit.SECONDS));
                assertTrue(closing.ssl.sslCloseFuture().await(2,TimeUnit.SECONDS),
                        "proxy did not answer close_notify while the client TCP socket remained open");
                assertTrue(closing.ssl.sslCloseFuture().isSuccess(),"proxy did not close TLS orderly");
                assertTrue(closing.channel.closeFuture().await(2,TimeUnit.SECONDS),"proxy TCP socket stayed open");
                assertTrue(tor.closed.await(2,TimeUnit.SECONDS),"closing device's upstream stayed open");
                var field=ProxyServer.class.getDeclaredField("admission");field.setAccessible(true);
                var occupancy=((Admission)field.get(proxy)).occupancy;
                long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
                while(occupancy.get()!=1 && System.nanoTime()<until) Thread.sleep(5);
                assertEquals(1,occupancy.get(),"closing device's connection slot stayed occupied");
                assertEquals(1,tor.sockets.size(),"only the survivor's upstream should remain");
                survivor.echo("after-close");
                try(var replacement=new TlsTunnel(group,context,tlsPort,"closing",token)) {
                    replacement.echo("reused-slot");survivor.echo("while-replacement-connected");
                    assertEquals(3,tor.seen.size(),"replacement must reach the synthetic SOCKS upstream");
                }
            } finally { group.shutdownGracefully(0,2,TimeUnit.SECONDS).sync(); }
        }
    }

    private static final class TlsTunnel implements AutoCloseable {
        final io.netty.channel.Channel channel;
        final io.netty.handler.ssl.SslHandler ssl;
        private final java.util.concurrent.BlockingQueue<Byte> received=new java.util.concurrent.LinkedBlockingQueue<>();

        TlsTunnel(io.netty.channel.EventLoopGroup group,io.netty.handler.ssl.SslContext context,
                int port,String profile,String token) throws Exception {
            var bootstrap=new io.netty.bootstrap.Bootstrap().group(group)
                    .channel(io.netty.channel.socket.nio.NioSocketChannel.class)
                    .handler(new io.netty.channel.ChannelInitializer<io.netty.channel.socket.SocketChannel>() {
                        @Override protected void initChannel(io.netty.channel.socket.SocketChannel ch) {
                            var handler=context.newHandler(ch.alloc(),"localhost",port);
                            var parameters=handler.engine().getSSLParameters();
                            parameters.setEndpointIdentificationAlgorithm("HTTPS");
                            handler.engine().setSSLParameters(parameters);
                            ch.pipeline().addLast(handler,new io.netty.channel.SimpleChannelInboundHandler<io.netty.buffer.ByteBuf>() {
                                @Override protected void channelRead0(io.netty.channel.ChannelHandlerContext ctx,io.netty.buffer.ByteBuf bytes) {
                                    while(bytes.isReadable()) received.add(bytes.readByte());
                                }
                            });
                        }
                    });
            channel=bootstrap.connect("127.0.0.1",port).sync().channel();
            ssl=channel.pipeline().get(io.netty.handler.ssl.SslHandler.class);
            try {
                assertTrue(ssl.handshakeFuture().await(2,TimeUnit.SECONDS),"TLS handshake timed out");
                assertTrue(ssl.handshakeFuture().isSuccess(),()->"TLS handshake failed: "+ssl.handshakeFuture().cause());
                String host="a".repeat(56)+".onion";
                String authorization=java.util.Base64.getEncoder().encodeToString((profile+":"+token).getBytes(StandardCharsets.US_ASCII));
                write("CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\nProxy-Authorization: Basic "+authorization+"\r\n\r\n");
                var headers=new StringBuilder();
                while(!headers.toString().endsWith("\r\n\r\n") && headers.length()<16384) headers.append((char)(readByte()&255));
                assertTrue(headers.toString().startsWith("HTTP/1.1 200"),headers.toString());
            } catch(Exception | AssertionError failure) { channel.close().syncUninterruptibly();throw failure; }
        }
        private void write(String value) throws Exception {
            channel.writeAndFlush(io.netty.buffer.Unpooled.copiedBuffer(value,StandardCharsets.US_ASCII)).sync();
        }
        private byte readByte() throws Exception {
            Byte value=received.poll(2,TimeUnit.SECONDS);
            assertNotNull(value,"no bytes received from TLS tunnel");return value;
        }
        void echo(String value) throws Exception {
            assertTrue(channel.isActive(),"surviving tunnel closed");write(value);
            byte[] bytes=new byte[value.length()];for(int i=0;i<bytes.length;i++) bytes[i]=readByte();
            assertEquals(value,new String(bytes,StandardCharsets.US_ASCII));
        }
        @Override public void close() { channel.close().syncUninterruptibly(); }
    }

}
