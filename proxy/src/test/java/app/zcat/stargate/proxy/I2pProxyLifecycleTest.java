// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;
import static org.junit.jupiter.api.Assertions.*;
import java.net.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Real Netty Front/Back teardown with controlled reload acknowledgments; not a public-network proof. */
class I2pProxyLifecycleTest {
    @TempDir Path directory;
    static final String TOKEN="synthetic-lifecycle-test-token-0123456789";
    void ack() throws Exception {
        String generation=Files.readString(directory.resolve("tunnels.conf")).split("generation=",2)[1].split("\n",2)[0];
        Files.writeString(directory.resolve("resources"),System.currentTimeMillis()/1000+" 1000 400000000 20 128 123\n");
        Files.writeString(directory.resolve("tunnels.conf.applied"),generation+" 123\n");
    }
    boolean published(int port) throws Exception{return Files.readString(directory.resolve("tunnels.conf")).contains("port="+port+"\n");}
    interface Check {boolean get() throws Exception;}
    void await(Check check) throws Exception {long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);while(!check.get()){Files.writeString(directory.resolve("resources"),System.currentTimeMillis()/1000+" 1000 400000000 20 128 123\n");assertTrue(System.nanoTime()<until,"condition deadline");Thread.sleep(20);}}
    Socket request(ProxyServer proxy,String device) throws Exception {
        Socket s=new Socket("127.0.0.1",proxy.port());s.setSoTimeout(4000);
        String auth=Base64.getEncoder().encodeToString((device+":"+TOKEN).getBytes(StandardCharsets.US_ASCII));
        s.getOutputStream().write(("CONNECT fixture.i2p:443 HTTP/1.1\r\nHost: fixture.i2p:443\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));return s;
    }
    void echo(Socket socket) throws Exception {socket.getOutputStream().write(42);assertEquals(42,socket.getInputStream().read());}
    @Test void explicitlySharedRouteStillWorksWithLifecycleDirectoryConfigured() throws Exception {
        try(var route=new ProxyServerTest.FakeTor(ProxyServerTest.Mode.ECHO,true)) {
            var profile=new ProxyConfig.Profile(ProxyConfig.digest(TOKEN.getBytes(StandardCharsets.US_ASCII)),"shared",-1);
            var config=new ProxyConfig(new InetSocketAddress("127.0.0.1",0),new InetSocketAddress("127.0.0.1",9050),Map.of("shared",profile),8,4000,1000,false,null,new InetSocketAddress("127.0.0.1",route.listener.getLocalPort()),4000,null,4000,directory,1);
            try(var proxy=new ProxyServer(config).start();var socket=request(proxy,"shared")) {
                StringBuilder headers=new StringBuilder();while(!headers.toString().endsWith("\r\n\r\n")){int c=socket.getInputStream().read();assertTrue(c>=0);headers.append((char)c);}
                assertTrue(headers.toString().startsWith("HTTP/1.1 200"));echo(socket);assertFalse(Files.readString(directory.resolve("tunnels.conf")).contains("type=socks"));
            }
        }
    }
    @Test void cancelledActivationAndHungSocksReleaseOnlyTheirOwnLease() throws Exception {
        int heldPort, absent, hangingPort, proxyPort;
        // Reserve distinct ports only long enough to choose them; admission must see them unoccupied.
        try (var heldReservation=new ServerSocket(0); var pendingReservation=new ServerSocket(0);
             var hangingReservation=new ServerSocket(0); var proxyReservation=new ServerSocket(0)) {
            heldPort=heldReservation.getLocalPort();absent=pendingReservation.getLocalPort();hangingPort=hangingReservation.getLocalPort();proxyPort=proxyReservation.getLocalPort();
        }
        var profiles=new HashMap<String,ProxyConfig.Profile>();var ports=Map.of("held",heldPort,"pending",absent,"hanging",hangingPort);
        ports.forEach((id,port)->profiles.put(id,new ProxyConfig.Profile(ProxyConfig.digest(TOKEN.getBytes(StandardCharsets.US_ASCII)),id,port)));
        var config=new ProxyConfig(new InetSocketAddress("127.0.0.1",proxyPort),new InetSocketAddress("127.0.0.1",9050),profiles,16,4000,1000,false,null,new InetSocketAddress("127.0.0.1",4447),15000,null,4000,directory,1);
        try(var proxy=new ProxyServer(config).start();var held=request(proxy,"held")) {
            ack();await(()->published(heldPort));
            // Native opens its listener only after the lifecycle publishes the port.
            try (var route=new ProxyServerTest.FakeTor(ProxyServerTest.Mode.ECHO,true,heldPort)) {
                ack();
                var input=held.getInputStream();StringBuilder headers=new StringBuilder();while(!headers.toString().endsWith("\r\n\r\n")){int c=input.read();assertTrue(c>=0);headers.append((char)c);}assertTrue(headers.toString().startsWith("HTTP/1.1 200"));echo(held);
                try(var cancelled=request(proxy,"pending")) {await(()->published(absent));} // Close before native acknowledgment/listener.
                ack();await(()->!published(absent));assertTrue(published(heldPort));echo(held);ack();
                try(var cancelled=request(proxy,"hanging")) {
                    await(()->published(hangingPort));
                    try(var hanging=new ProxyServerTest.FakeTor(ProxyServerTest.Mode.HANG,true,hangingPort)) {
                        ack();assertTrue(hanging.hangingInput.await(4,TimeUnit.SECONDS));
                        assertEquals(1,hanging.hangingPeerClosed.getCount()); // The upstream remains open until cancellation.
                        cancelled.close(); // Exercise teardown after the SOCKS negotiation actually hangs.
                        assertTrue(hanging.hangingPeerClosed.await(4,TimeUnit.SECONDS));
                        await(()->!published(hangingPort));assertTrue(published(heldPort));echo(held);
                    }
                }
            }
        }
        assertFalse(published(heldPort)); // Graceful proxy stop clears fleet.
    }
}
