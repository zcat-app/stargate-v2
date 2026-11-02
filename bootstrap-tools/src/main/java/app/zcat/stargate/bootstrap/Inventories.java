/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;

import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.apache.commons.compress.archivers.tar.*;

final class Inventories {
  static boolean regularMember(TarArchiveEntry member) {
    // Commons Compress isFile() also accepts links/devices when their names lack a slash.
    byte type = member.getLinkFlag();
    return type == TarConstants.LF_NORMAL
        || type == TarConstants.LF_OLDNORM
        || type == TarConstants.LF_CONTIG
        || member.isSparse();
  }

  static ObjectNode source(Path root) throws Exception {
    directory(root);
    need(mode(root) == 0755, "Source root mode mismatch");
    ObjectNode entries = JSON.createObjectNode();
    long total = 0;
    try (var paths = Files.walk(root)) {
      for (Path path : paths.filter(p -> !p.equals(root)).toList()) {
        need(entries.size() < 100000, "Too many source entries");
        String relative = root.relativize(path).toString();
        var data = info(path);
        int mode = ((Number) data.get("mode")).intValue();
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
          need((mode & 07777) == 0755, "Source directory mode mismatch");
          entries.set(relative, JSON.valueToTree(List.of("directory")));
        } else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
          long size = ((Number) data.get("size")).longValue();
          total += size;
          need(
              size <= 256L * 1024 * 1024 && total <= 1024L * 1024 * 1024,
              "Source size limit exceeded");
          need((mode & 07777) == 0644 || (mode & 07777) == 0755, "Source file mode mismatch");
          ArrayNode entry = JSON.createArrayNode().add("file").add(size).add(sha(path));
          entries.set(relative, entry);
        } else if (Files.isSymbolicLink(path))
          entries.set(
              relative,
              JSON.valueToTree(List.of("symlink", Files.readSymbolicLink(path).toString())));
        else throw new java.io.IOException("Unsupported source entry: " + relative);
      }
    }
    return entries;
  }

  static ObjectNode tar(Path path) throws Exception {
    regular(path, true);
    need(Files.size(path) <= 2L * 1024 * 1024 * 1024, "Source archive size limit exceeded");
    ObjectNode entries = JSON.createObjectNode();
    boolean root = false;
    long total = 0;
    try (var input =
        new TarArchiveInputStream(Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS))) {
      for (TarArchiveEntry member; (member = input.getNextEntry()) != null; ) {
        need(member.isCheckSumOK(), "Tar header checksum mismatch");
        need(entries.size() < 100000, "Too many archive entries");
        String name = member.getName();
        if (name.startsWith("./")) name = name.substring(2);
        name = name.replaceAll("/+$", "");
        if (name.equals("glibc-2.39")) {
          need(
              !root && member.isDirectory() && member.getMode() == 0755,
              "Invalid/duplicate source archive root");
          root = true;
          continue;
        }
        need(name.startsWith("glibc-2.39/"), "Unexpected archive path");
        String relative = name.substring("glibc-2.39/".length());
        need(
            !relative.isEmpty()
                && Arrays.stream(relative.split("/", -1))
                    .noneMatch(p -> List.of("", ".", "..").contains(p))
                && !entries.has(relative),
            "Invalid/duplicate archive member");
        if (member.isDirectory()) {
          need(member.getMode() == 0755, "Copied directory mode mismatch");
          entries.set(relative, JSON.valueToTree(List.of("directory")));
        } else if (member.isSymbolicLink()) {
          entries.set(relative, JSON.valueToTree(List.of("symlink", member.getLinkName())));
        } else if (regularMember(member)) {
          long size = member.getSize();
          total += size;
          need(
              size >= 0 && size <= 256L * 1024 * 1024 && total <= 1024L * 1024 * 1024,
              "Copied source size limit exceeded");
          need(member.getMode() == 0644 || member.getMode() == 0755, "Copied file mode mismatch");
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
          byte[] buffer = new byte[65536];
          long read = 0;
          for (int n; (n = input.read(buffer)) != -1; ) {
            read += n;
            digest.update(buffer, 0, n);
          }
          need(read == size, "Truncated copied source entry");
          entries.set(
              relative,
              JSON.createArrayNode()
                  .add("file")
                  .add(size)
                  .add(HexFormat.of().formatHex(digest.digest())));
        } else throw new java.io.IOException("Unsupported archive member");
      }
    }
    need(root, "Source archive root missing");
    return entries;
  }
}
