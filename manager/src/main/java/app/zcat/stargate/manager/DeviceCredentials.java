// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.*;

/** One manager writes atomic snapshots; no browsing information is stored here. */
final class DeviceCredentials {
    record Device(String id, String token) {}
    private final Path path;
    private final Path tunnels;
    DeviceCredentials(Path path) { this(path, null); }
    DeviceCredentials(Path path, Path tunnels) { this.path = path; this.tunnels = tunnels; }
    synchronized boolean i2pOnDemand() {
        try { return read().containsKey("i2p.lifecycleDirectory"); }
        catch(Exception e) { return false; }
    }
    synchronized I2pDeviceStatus.Observation i2pStatus(String id, ProxyControl.Unit process) {
        try {
            Properties p=read();
            if(!tokens(p).containsKey(id))return I2pDeviceStatus.unavailable();
            if(!"true".equals(p.getProperty("i2p.deviceIsolation"))||!p.containsKey("i2p.lifecycleDirectory"))
                return new I2pDeviceStatus.Observation("NOT_CONFIGURED",null);
            if("false".equals(p.getProperty("profile."+id+".i2pEnabled")))return new I2pDeviceStatus.Observation("DISABLED",null);
            int port=Integer.parseInt(p.getProperty("profile."+id+".i2pPort","0"));
            if(port<14447||port>65535)return I2pDeviceStatus.unavailable();
            return I2pDeviceStatus.read(Path.of(p.getProperty("i2p.lifecycleDirectory")).resolve("status.json"),port,process);
        } catch(Exception e){return I2pDeviceStatus.unavailable();}
    }
    synchronized int i2pPort(String id) {
        try {
            Properties p = read();
            if (!p.getProperty("i2p.deviceIsolation", "false").equals("true")) return -1;
            if (p.getProperty("profile." + id + ".i2pEnabled", "true").equals("false")) return 0;
            return Integer.parseInt(p.getProperty("profile." + id + ".i2pPort", "0"));
        } catch (Exception e) { return 0; }
    }
    synchronized void setI2pEnabled(String id, boolean enabled) {
        try {
            Properties p = read();
            if (!tokens(p).containsKey(id) || !p.getProperty("i2p.deviceIsolation", "false").equals("true"))
                throw new IllegalArgumentException("I2P_DEVICE_NOT_CONFIGURED");
            p.setProperty("profile." + id + ".i2pEnabled", Boolean.toString(enabled)); write(p);
        } catch (IOException e) { throw new IllegalStateException("DEVICE_STORE_UNAVAILABLE"); }
    }

    /** Persistent ports are never recycled: delayed reload must not expose a previous identity. */
    synchronized void reconcileI2p() {
        if (tunnels == null) return;
        try {
            Properties p = read();
            if (!p.getProperty("i2p.deviceIsolation", "false").equals("true")) return;
            var ids = tokens(p).keySet().stream().sorted().toList();

            if (allocateI2pPorts(p, ids)) write(p);
            // The proxy alone publishes the active fleet; a manager restart cannot evict streams.
        } catch (Exception e) { throw new IllegalStateException("I2P_DEVICE_CONFIGURATION_UNAVAILABLE"); }
    }
    /** A saved mapping needs no new allocation; validate the entire fleet before offering Enable. */
    synchronized boolean canEnableI2p(String id, boolean allocationAvailable) {
        try {
            Properties p = read();
            if (!"true".equals(p.getProperty("i2p.deviceIsolation"))) return false;
            var ids = tokens(p).keySet().stream().sorted().toList();
            int next = validateI2pPorts(p, ids);
            return ids.contains(id) && (p.containsKey("profile." + id + ".i2pPort")
                    || (allocationAvailable && next < 65536));
        } catch (Exception e) { return false; }
    }

    private static boolean allocateI2pPorts(Properties p, java.util.List<String> ids) throws IOException {
        int next = validateI2pPorts(p, ids);
        boolean changed = false;
        for (String id : ids) if (!p.containsKey("profile." + id + ".i2pPort")) {
            if (next > 65535) throw new IOException("I2P_PORTS_EXHAUSTED");
            p.setProperty("profile." + id + ".i2pPort", Integer.toString(next++)); changed = true;
        }
        p.setProperty("i2p.nextPort", Integer.toString(next));
        return changed;
    }

    private static int validateI2pPorts(Properties p, java.util.List<String> ids) throws IOException {
        int next = Integer.parseInt(p.getProperty("i2p.nextPort"));
        if (next < 14447 || next > 65536) throw new IOException("INVALID_I2P_PORT_SEQUENCE");
        var ports = new HashSet<Integer>();
        for (String id : ids) {
            String enabled=p.getProperty("profile."+id+".i2pEnabled","true");
            if(!enabled.equals("true")&&!enabled.equals("false"))throw new IOException("INVALID_I2P_DEVICE_SETTING");
            String value = p.getProperty("profile." + id + ".i2pPort");
            if (value != null) {
                int port = Integer.parseInt(value);
                if (port < 14447 || port >= next || !ports.add(port)) throw new IOException("INVALID_I2P_PORT");
            }
        }
        return next;
    }

    synchronized Map<String, String> tokens() {
        try { return tokens(read()); }
        catch (IOException | IllegalArgumentException e) { throw new IllegalStateException("DEVICE_STORE_UNAVAILABLE"); }
    }
    private Properties read() throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 262144)
            throw new IOException("INVALID_DEVICE_STORE");
        return ManagerSettings.privateProperties(path);
    }
    private static Map<String, String> tokens(Properties properties) {
        Map<String, String> result = new HashMap<>();
        for (String name : properties.stringPropertyNames()) if (name.startsWith("profile.") && name.endsWith(".token")) {
            String id = name.substring(8, name.length() - 6), token = properties.getProperty(name);
            if (!id.matches("[A-Za-z0-9_-]{1,64}") || !token.matches("[A-Za-z0-9_-]{32,128}"))
                throw new IllegalArgumentException("INVALID_DEVICE_CREDENTIAL");
            result.put(id, token);
        }
        return Map.copyOf(result);
    }
    static void validateLabel(String label) {
        if (label == null || !label.matches("[A-Za-z0-9_-]{1,32}")) throw new IllegalArgumentException("INVALID_DEVICE_LABEL");
    }
    synchronized void requireCapacity() {
        try {
            Properties p = read();
            tokens(p);
        } catch (IOException | IllegalArgumentException e) { throw new IllegalStateException("DEVICE_STORE_UNAVAILABLE"); }
    }
    synchronized Device create(String label) {
        validateLabel(label);
        try {
            Properties properties = read();
            Map<String, String> existing = tokens(properties);
            String id;
            do { id = "d_" + label + "_" + random(12); } while (existing.containsKey(id));
            String token = random(32);
            properties.setProperty("profile." + id + ".token", token);
            // Publish the credential and its route in the same atomic snapshot.
            if (tunnels != null && "true".equals(properties.getProperty("i2p.deviceIsolation")))
                allocateI2pPorts(properties, tokens(properties).keySet().stream().sorted().toList());
            write(properties);
            return new Device(id, token);
        } catch (IOException | IllegalArgumentException e) { throw new IllegalStateException("DEVICE_STORE_UNAVAILABLE"); }
    }
    synchronized boolean revoke(String id) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException("INVALID_DEVICE_ID");
        try {
            Properties properties = read();tokens(properties);
            if (properties.remove("profile." + id + ".token") == null) return false;
            properties.remove("profile." + id + ".i2pPort");
            properties.remove("profile." + id + ".i2pEnabled");
            write(properties);return true;
        } catch (IOException | IllegalArgumentException e) { throw new IllegalStateException("DEVICE_STORE_UNAVAILABLE"); }
    }
    private void write(Properties properties) throws IOException {
        Path temporary = Files.createTempFile(path.getParent(), ".devices-", ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            try (var writer = Files.newBufferedWriter(temporary)) { properties.store(writer, "Stargate private configuration"); }
            if (Files.size(temporary) > 262144) throw new IllegalStateException("DEVICE_STORE_FULL");
            try (var channel = java.nio.channels.FileChannel.open(temporary, StandardOpenOption.WRITE)) { channel.force(true); }
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            try (var directory = java.nio.channels.FileChannel.open(path.getParent(), StandardOpenOption.READ)) { directory.force(true); }
        } finally { Files.deleteIfExists(temporary); }
    }
    private static String random(int length) {
        byte[] bytes = new byte[length];new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
