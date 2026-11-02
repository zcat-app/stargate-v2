// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class I2pDeviceStatusTest {
    @TempDir Path directory;
    ProxyControl.Unit process(){return new ProxyControl.Unit("OBSERVED","loaded","active","running",ProcessHandle.current().pid(),"","success",0,"TEST");}
    void write(Instant at,String start) throws Exception {
        Files.writeString(directory.resolve("status.json"),"{\"pid\":"+ProcessHandle.current().pid()+",\"startedAt\":\""+start+"\",\"observedAt\":\""+at+"\",\"available\":true,\"devices\":{\"14447\":\"CONNECTIONS_OPEN\",\"14448\":\"STARTING\"}}");
    }
    String start(){return ProcessHandle.current().info().startInstant().orElseThrow().toString();}
    String state(int port){return I2pDeviceStatus.read(directory.resolve("status.json"),port,process()).state();}
    @Test void selectsOnlyRequestedDeviceAndRejectsStaleFutureReusedPidAndStoppedProcess() throws Exception {
        write(Instant.now(),start());assertEquals("CONNECTIONS_OPEN",state(14447));assertEquals("STARTING",state(14448));assertEquals("NOT_STARTED",state(14449));
        write(Instant.now().minusSeconds(6),start());assertEquals("UNAVAILABLE",state(14447));
        write(Instant.now().plusSeconds(60),start());assertEquals("UNAVAILABLE",state(14447));
        write(Instant.now(),Instant.EPOCH.toString());assertEquals("UNAVAILABLE",state(14447));
        write(Instant.now(),start());var stopped=new ProxyControl.Unit("OBSERVED","loaded","inactive","dead",0L,"","success",0,"TEST");
        assertEquals("UNAVAILABLE",I2pDeviceStatus.read(directory.resolve("status.json"),14447,stopped).state());
    }
    @Test void rejectsMalformedOversizedSymlinkAndUnconfirmedSnapshots() throws Exception {
        Path file=directory.resolve("status.json");
        for(String replacement:new String[]{"\"available\":false","\"available\":true,\"destination\":\"forbidden\""}) {
            write(Instant.now(),start());Files.writeString(file,Files.readString(file).replace("\"available\":true",replacement));assertEquals("UNAVAILABLE",state(14447));
        }
        write(Instant.now(),start());Files.writeString(file,Files.readString(file).replace("STARTING","READY"));assertEquals("UNAVAILABLE",state(14447));
        Files.writeString(file,"x".repeat(2097153));assertEquals("UNAVAILABLE",state(14447));
        Files.move(file,directory.resolve("other"));Files.createSymbolicLink(file,Path.of("other"));assertEquals("UNAVAILABLE",state(14447));
    }
    @Test void deviceConfigurationSeparatesDisabledFromUnavailableAndNeverReturnsAnotherDevice() throws Exception {
        Path config=directory.resolve("proxy.properties");
        String base="i2p.deviceIsolation=true\ni2p.lifecycleDirectory="+directory+"\nprofile.one.token="+"a".repeat(43)+"\nprofile.one.i2pPort=14447\nprofile.two.token="+"b".repeat(43)+"\nprofile.two.i2pPort=14448\n";
        Files.writeString(config,base);Files.setPosixFilePermissions(config,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        var devices=new DeviceCredentials(config);write(Instant.now(),start());
        assertEquals("CONNECTIONS_OPEN",devices.i2pStatus("one",process()).state());assertEquals("STARTING",devices.i2pStatus("two",process()).state());
        assertEquals("UNAVAILABLE",devices.i2pStatus("missing",process()).state());
        Files.writeString(config,base+"profile.one.i2pEnabled=false\n");assertEquals("DISABLED",devices.i2pStatus("one",process()).state());
        Files.writeString(config,base.replace("profile.one.i2pPort=14447","profile.one.i2pPort=0"));assertEquals("UNAVAILABLE",devices.i2pStatus("one",process()).state());
        Files.delete(config);assertEquals("UNAVAILABLE",devices.i2pStatus("one",process()).state());
    }
}
