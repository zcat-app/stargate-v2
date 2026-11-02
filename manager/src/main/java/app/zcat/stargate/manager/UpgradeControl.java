// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import com.fasterxml.jackson.databind.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;

/** Narrow untrusted request channel; all release authority remains in the host updater. */
final class UpgradeControl {
    private static final ObjectMapper JSON=new ObjectMapper();
    private final Path directory;
    UpgradeControl(Path directory){this.directory=directory;}
    JsonNode observation() {
        if(directory==null)return null;
        try {
            Path p=directory.resolve("public/status.json");
            if(!Files.isRegularFile(p,NOFOLLOW_LINKS))return null;
            byte[] bytes;try(var in=Files.newInputStream(p,NOFOLLOW_LINKS)){bytes=in.readNBytes(65537);}if(bytes.length>65536)return null;
            JsonNode n=JSON.readTree(bytes);
            if(n.path("schema").asInt()!=1||!Set.of("EMPTY","PREPARED","INSTALLING","INSTALLED","INSTALL_FAILED","ROLLING_BACK","ROLLED_BACK","ROLLBACK_FAILED","REVIEW_REQUIRED","UNCERTAIN").contains(n.path("phase").asText()))return null;
            long age=Instant.now().getEpochSecond()-Instant.parse(n.path("observedAt").asText()).getEpochSecond();
            if(age<0||age>15||!n.path("signer").asText().matches("[a-f0-9]{64}"))return null;
            if(!n.path("phase").asText().equals("EMPTY")&&(!n.path("plan").asText().matches("[a-f0-9]{64}")||!n.path("release").path("changes").isArray()))return null;
            return n;
        }catch(Exception e){return null;}
    }
    synchronized boolean request(String action,String plan) {
        JsonNode n=observation();if(n==null||!Set.of("refresh","install","rollback").contains(action))return false;
        String phase=n.path("phase").asText();
        if(action.equals("refresh")){if(!Set.of("EMPTY","PREPARED","INSTALLED","ROLLED_BACK","REVIEW_REQUIRED").contains(phase))return false;}
        else {
            if(plan==null||!plan.matches("[a-f0-9]{64}")||!plan.equals(n.path("plan").asText()))return false;
            if(action.equals("install")&&(!phase.equals("PREPARED")||!Instant.parse(n.path("release").path("expiresAt").asText()).isAfter(Instant.now())))return false;
            if(action.equals("rollback")&&!Set.of("INSTALLED","INSTALLING","INSTALL_FAILED","ROLLING_BACK","ROLLBACK_FAILED").contains(phase))return false;
        }
        Path tmp=null;
        try {
            Path inbox=directory.resolve("inbox");tmp=Files.createTempFile(inbox,".request-","",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--")));
            Files.setPosixFilePermissions(tmp,PosixFilePermissions.fromString("rw-r--r--"));
            byte[] body=JSON.writeValueAsBytes(Map.of("action",action,"plan",action.equals("refresh")?"":plan));
            try(var out=java.nio.channels.FileChannel.open(tmp,StandardOpenOption.WRITE)){var buffer=java.nio.ByteBuffer.wrap(body);while(buffer.hasRemaining())if(out.write(buffer)<=0)throw new java.io.IOException("WRITE_STALLED");out.force(true);}
            Files.createLink(inbox.resolve("request.json"),tmp);return true;
        } catch(Exception e){return false;}finally{if(tmp!=null)try{Files.deleteIfExists(tmp);}catch(Exception ignored){}}
    }
    String html(WebSessions.Session session) {
        if(directory==null)return "";
        JsonNode n=observation();StringBuilder h=new StringBuilder("<section id=\"upgrades\"><h2>Software upgrades</h2>");
        if(n==null)return h.append("<p>Host updater unavailable or its observation is stale. No upgrade action is available.</p></section>").toString();
        String phase=n.path("phase").asText(),plan=n.path("plan").asText();
        h.append("<p>Transaction: <strong>").append(WebUi.escape(phase)).append("</strong>. Refresh this page to observe progress.</p>");
        if(n.has("error"))h.append("<p role=\"alert\">The last request failed. Inspect the host updater log before retrying.</p>");
        if(n.has("release")) {
            JsonNode r=n.path("release");h.append("<h3>Release ").append(WebUi.escape(r.path("release").asText())).append("</h3><p>Release plan signature verified with pinned Ed25519 public-key fingerprint:</p><code>").append(WebUi.escape(n.path("signer").asText())).append("</code>");
            h.append("<p>Source commit: <code>").append(WebUi.escape(r.path("sourceCommit").asText())).append("</code>. Plan expires: ").append(WebUi.escape(r.path("expiresAt").asText())).append(".</p><ul>");
            for(var c:r.path("changes"))h.append("<li>").append(WebUi.escape(c.path("service").asText())).append(": ").append(WebUi.escape(c.path("fromVersion").asText())).append(" → ").append(WebUi.escape(c.path("toVersion").asText())).append("<br>Before this transaction: <code>").append(WebUi.escape(c.path("fromImage").asText())).append("</code><br>Upgrade target: <code>").append(WebUi.escape(c.path("toImage").asText())).append("</code></li>");
            h.append("</ul><p>Versions and source provenance are the release signer's declarations. Installation verifies downloaded archive hashes, exact image IDs, retained patch inventory and configured runtime bytes before replacing services.</p><details><summary>Retained source patches</summary><ul>");
            for(var p:r.path("patches").properties())h.append("<li>").append(WebUi.escape(p.getKey())).append(" <code>").append(WebUi.escape(p.getValue().asText())).append("</code></li>");
            h.append("</ul></details><p>Affected services restart; their open connections can break. Updating app briefly removes this manager. Saved access and existing volume data are kept. State migrations are unsupported. Rollback restores recorded images with the latest data; it does not undo data changes or prove destination access. Keep the host recovery command available.</p>");
            if(phase.equals("PREPARED")&&Instant.parse(r.path("expiresAt").asText()).isAfter(Instant.now()))h.append(form(session,"install",plan,"Install reviewed upgrade"));
            if(Set.of("INSTALLED","INSTALLING","INSTALL_FAILED","ROLLING_BACK","ROLLBACK_FAILED").contains(phase))h.append(form(session,"rollback",plan,"Roll back to previous images"));
        }
        if(Set.of("EMPTY","PREPARED","INSTALLED","ROLLED_BACK","REVIEW_REQUIRED").contains(phase))h.append(form(session,"refresh","","Review available upgrade"));
        if(phase.equals("UNCERTAIN"))h.append("<p role=\"alert\">The Docker command timed out. Host inspection and recovery are required; automatic actions are blocked.</p>");
        return h.append("<p>Before installing, retain a verified backup and check this release's compatibility notes. Refreshing after an installed release starts a new transaction and replaces the rollback button's target; prior records remain on the host.</p></section>").toString();
    }
    private static String form(WebSessions.Session s,String action,String plan,String label) {
        return "<form method=\"post\" action=\"/upgrades/"+action+"\"><input type=\"hidden\" name=\"csrf\" value=\""+WebUi.escape(s.csrf())+"\"><input type=\"hidden\" name=\"plan\" value=\""+WebUi.escape(plan)+"\"><button type=\"submit\">"+label+"</button></form>";
    }
}
