// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import static org.junit.jupiter.api.Assertions.*;

class SelectionFileTest {
    @TempDir Path temp;
    @Test void requiresPrivateStableRegularSelectionAndRejectsLinks() throws Exception {
        Path file=temp.resolve("selection");Files.writeString(file,"{\"version\":1,\"volumes\":{\"app-data\":\"a\",\"tor-data\":\"b\",\"tor-control\":\"c\",\"i2p-data\":\"d\",\"i2p-control\":\"e\"},\"containers\":[]}");
        Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"));int uid=Linux.uid("geteuid");
        assertEquals(5,DockerPolicy.readSelection(file,false,uid).volumes().size());
        Path link=temp.resolve("link");Files.createSymbolicLink(link,file);assertThrows(Exception.class,()->DockerPolicy.readSelection(link,false,uid));
        Path hard=temp.resolve("hard");Files.createLink(hard,file);assertThrows(Exception.class,()->DockerPolicy.readSelection(file,false,uid));Files.delete(hard);
        Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-r--r--"));assertThrows(Exception.class,()->DockerPolicy.readSelection(file,false,uid));
    }
}
