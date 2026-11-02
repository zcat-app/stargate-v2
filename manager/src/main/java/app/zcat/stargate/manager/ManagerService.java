// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

@Startup
@ApplicationScoped
public class ManagerService {
    public record ProxyObservation(String state, String code, Boolean ownedByProcess) {}
    public record Status(String observedAt, String controller, String unit, ProxyControl.Unit process,
                         ProxyObservation proxy, TorProbe.Observation tor, I2pProbe.Observation i2p, NymProbe.Observation nym, I2pDeviceStatus.Observation i2pDevice) {}
    public record Operation(String action, boolean success, String code, Status status) {}
    private final ManagerSettings settings;
    private final int port;
    private final ProxyControl processControl;
    private final Pairing pairing;
    private final DeviceCredentials devices;
    private final java.util.concurrent.ScheduledExecutorService i2pConfiguration;
    private volatile boolean i2pConfigurationAvailable;
    private final ReentrantLock operations = new ReentrantLock();
    private final WebSessions sessions = new WebSessions(java.time.Clock.systemUTC());

    @Inject
    public ManagerService(@ConfigProperty(name = "stargate.config") String file,
                          @ConfigProperty(name = "quarkus.http.host") String host,
                          @ConfigProperty(name = "quarkus.http.port") int port) throws IOException {
        settings = ManagerSettings.load(Path.of(file));this.port = port;
        if ((!host.equals("127.0.0.1") && !(host.equals("0.0.0.0") && settings.controlSocket() != null))
                || port < 1 || port > 65535) throw new IllegalArgumentException("MANAGER_REQUIRES_LOOPBACK_OR_CONTAINER");
        processControl = settings.controlSocket() == null ? new SystemdProxy(settings.unit()) : new SupervisedProxy(settings.controlSocket());
        devices = new DeviceCredentials(settings.proxyFile(), settings.controlSocket() == null ? null : Path.of("/run/i2p-control/tunnels.conf"));
        try { devices.reconcileI2p(); i2pConfigurationAvailable = true; }
        catch (Exception ignored) { i2pConfigurationAvailable = false; }
        i2pConfiguration = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(task -> Thread.ofPlatform().daemon().name("i2p-device-configuration").unstarted(task));
        i2pConfiguration.scheduleWithFixedDelay(() -> {
            try { devices.reconcileI2p(); i2pConfigurationAvailable = true; }
            catch (Throwable ignored) { i2pConfigurationAvailable = false; }
        }, 1, 1, java.util.concurrent.TimeUnit.SECONDS);
        pairing = new Pairing(settings.token(), devices, java.time.Clock.systemUTC());
    }
    @jakarta.annotation.PreDestroy void closeI2pConfiguration() { i2pConfiguration.shutdownNow(); }
    public boolean i2pConfigurationAvailable() { return i2pConfigurationAvailable; }
    UpgradeControl upgrades() { return new UpgradeControl(settings.upgradeDirectory()); }

    public String i2pLifecycleObservation() {
        if(!devices.i2pOnDemand())return "not enabled";
        try {
            Path directory=Path.of("/run/i2p-control");
            Path config=directory.resolve("tunnels.conf"),ack=directory.resolve("tunnels.conf.applied"),resources=directory.resolve("resources");
            if(java.nio.file.Files.size(config)>131072||java.nio.file.Files.size(ack)>128||java.nio.file.Files.size(resources)>256)return "unavailable";
            var matcher=java.util.regex.Pattern.compile("(?m)^generation=([a-f0-9]{32})$").matcher(java.nio.file.Files.readString(config));
            String[] sample=java.nio.file.Files.readString(resources).trim().split(" ");
            long age=System.currentTimeMillis()/1000-Long.parseLong(sample[0]);
            if(sample.length==6&&age>=0&&age<=5&&matcher.find()&&java.nio.file.Files.readString(ack).trim().equals(matcher.group(1)+" "+sample[5]))return "configuration applied; destination readiness unknown";
        }catch(Exception ignored){}
        return "awaiting confirmation or unavailable; new requests may fail while existing connections are retained";
    }

    public Status status() { return status(null); }
    private Status status(String device) {
        ProxyControl.Unit unit = processControl.sample();
        SocketProbe.Observation protocol = SocketProbe.proxy(settings.proxy());
        ProxyObservation proxy = new ProxyObservation(protocol.state(), protocol.code(), ListenerOwnership.sample(unit.pid(), settings.proxy()));
        TorProbe.Observation tor = TorProbe.sample(settings.control(), settings.cookie(), settings.socks());
        int devicePort = device == null ? -1 : devices.i2pPort(device);
        var i2pEndpoint = settings.i2pSocks();
        if (devicePort >= 0) i2pEndpoint = devicePort == 0 || i2pEndpoint == null ? null
                : new java.net.InetSocketAddress(i2pEndpoint.getHostString(), devicePort);
        var i2p = I2pProbe.sample(i2pEndpoint, settings.i2pControl(), settings.i2pPassword(), settings.i2pCertificate(), TrafficStats.read(settings.metrics(), unit));
        if (devicePort >= 0 && i2p.socks() != null && i2p.socks().state().equals("RESPONDING"))
            i2p = new I2pProbe.Observation("UNKNOWN", i2p.control(), "I2P_DEVICE_READINESS_UNKNOWN", i2p.sharedDestinationReady(),
                    i2p.activePeers(), i2p.inboundTunnels(), i2p.outboundTunnels(), i2p.version(), i2p.socks(), i2p.destinationAccess());
        if(devicePort>0 && devices.i2pOnDemand() && "active".equals(unit.activeState()) && i2p.socks()!=null
                && "REFUSED".equals(i2p.socks().state()) && "AUTHENTICATED".equals(i2p.control()))
            i2p = new I2pProbe.Observation("UNKNOWN",i2p.control(),"I2P_DEVICE_ON_DEMAND",i2p.sharedDestinationReady(),
                    i2p.activePeers(),i2p.inboundTunnels(),i2p.outboundTunnels(),i2p.version(),i2p.socks(),i2p.destinationAccess());
        return new Status(Instant.now().toString(), settings.controlSocket() == null ? "SYSTEMD" : "SUPERVISOR",
                settings.controlSocket() == null ? settings.unit() : null, unit, proxy, tor,
                i2p,
                NymProbe.sample(settings.nymSocks(), TrafficStats.read(settings.metrics(), unit)),
                device==null ? null : devices.i2pStatus(device,unit));
    }

    public String origin() { return settings.origin() == null ? "http://127.0.0.1:" + port : settings.origin(); }
    public String publicOrigin() { return settings.publicOrigin(); }
    private String proxyHost(boolean remote) { return !remote ? settings.proxy().getAddress().getHostAddress() : java.net.URI.create(publicOrigin()).getHost(); }
    private int proxyPort(boolean remote) { return !remote ? settings.publicProxyPort() : settings.remoteProxyPort(); }
    private String proxyScheme(boolean remote) { return !remote ? "http" : "https"; }
    public String authority() { return java.net.URI.create(origin()).getRawAuthority(); }
    WebSessions sessions() { return sessions; }
    java.nio.file.Path metricsPath() { return settings.metrics(); }
    ReleaseMonitor.Observation releaseMonitor() {
        return settings.releaseSnapshot() == null ? null : ReleaseMonitor.read(settings.releaseSnapshot(), settings.releaseMaxAge(), Instant.now());
    }
    ReleaseMonitor.ConsumerObservation consumerMonitor() {
        return settings.consumerSnapshot() == null ? null : ReleaseMonitor.readConsumer(settings.consumerSnapshot(), settings.consumerMaxAge(), Instant.now());
    }
    public java.util.List<String> profiles() { return devices.tokens().keySet().stream().sorted().toList(); }
    public Pairing.Ticket issuePairing(String label) { return issuePairing(label, null); }
    public Pairing.Ticket issuePairing(String label, String lifetime) { devices.requireCapacity(); return pairing.issue(label, lifetime); }
    public java.util.List<Pairing.Invitation> invitations() { return pairing.invitations(); }
    public boolean cancelInvitation(String id) { return pairing.cancel(id); }
    public boolean i2pDeviceIsolation() { return devices.i2pPort("") >= 0; }
    I2pDeviceStatus.Observation i2pDeviceStatus(String id, ProxyControl.Unit process) { return devices.i2pStatus(id,process); }
    public boolean i2pEnabled(String id) { return devices.i2pPort(id) > 0; }
    public boolean canEnableI2p(String id) {
        return devices.canEnableI2p(id, i2pConfigurationAvailable);
    }
    public void setI2pEnabled(String id, boolean enabled) { devices.setI2pEnabled(id, enabled); }
    public boolean revokeDevice(String id) { return devices.revoke(id); }
    public record Paired(Pairing.Redeemed credentials, String proxyHost, int proxyPort, String proxyScheme) {}
    public Paired redeemPairing(String code, String origin) { return redeemPairing(code, origin, false); }
    public Paired redeemPairing(String code, String origin, boolean remote) {
        Pairing.Redeemed credentials = pairing.redeem(code, origin);
        return credentials == null ? null : new Paired(credentials, proxyHost(remote), proxyPort(remote), proxyScheme(remote));
    }
    public boolean extensionAuthorized(String authorization, String origin) { return pairing.profile(authorization, origin) != null; }
    public record ExtensionStatus(String profileId, String proxyHost, int proxyPort, String proxyScheme, Status status) {}
    public ExtensionStatus extensionStatus(String authorization, String origin) { return extensionStatus(authorization, origin, false); }
    public ExtensionStatus extensionStatus(String authorization, String origin, boolean remote) {
        String profile = pairing.profile(authorization, origin);
        if (profile == null) throw new jakarta.ws.rs.WebApplicationException(401);
        return new ExtensionStatus(profile, proxyHost(remote), proxyPort(remote), proxyScheme(remote), status(profile));
    }
    public boolean authorized(String authorization) {
        if (authorization == null || authorization.length() > 1024) return false;
        return java.security.MessageDigest.isEqual(authorization.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                ("Bearer " + settings.token()).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    public Operation operate(String action) {
        if (!operations.tryLock()) return new Operation(action, false, "OPERATION_IN_PROGRESS", null);
        try {
            ProxyControl.Command command = processControl.action(action);
            if (!command.success()) return new Operation(action, false, command.code(), status());
            boolean stop = action.equals("stop");
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
            while (System.nanoTime() < deadline) {
                var process = processControl.sample();var proxy = SocketProbe.proxy(settings.proxy());
                boolean reached = stop ? "inactive".equals(process.activeState()) && Long.valueOf(0).equals(process.pid()) && proxy.state().equals("REFUSED")
                        : "active".equals(process.activeState()) && process.pid() != null && process.pid() > 0 && proxy.state().equals("RESPONDING")
                          && Boolean.TRUE.equals(ListenerOwnership.sample(process.pid(), settings.proxy()));
                if (reached) return new Operation(action, true, stop ? "PROXY_STOPPED" : "PROXY_RUNNING", status());
                if ("failed".equals(process.activeState())) return new Operation(action, false, "PROXY_PROCESS_FAILED", status());
                try { Thread.sleep(100); }
                catch (InterruptedException e) { Thread.currentThread().interrupt();return new Operation(action, false, "OPERATION_INTERRUPTED", null); }
            }
            return new Operation(action, false, "EXPECTED_STATE_NOT_OBSERVED", status());
        } finally { operations.unlock(); }
    }
}
