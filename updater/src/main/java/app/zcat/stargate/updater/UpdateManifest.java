// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import static app.zcat.stargate.updater.UpdateFiles.*;

record UpdateManifest(String id,JsonNode document) {
    static UpdateManifest verify(byte[] bytes,byte[] signature,byte[] key,String fingerprint,Instant now)throws Exception {
        require(bytes.length<=65536&&signature.length==64&&fingerprint.matches(HASH)&&hash(key).equals(fingerprint),"SIGNER_PIN_MISMATCH");
        var verifier=Signature.getInstance("Ed25519");verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(key)));verifier.update(bytes);
        require(verifier.verify(signature),"SIGNATURE_INVALID");
        JsonNode n=JSON.readTree(bytes);keys(n,"schema","release","sourceCommit","createdAt","expiresAt","statePolicy","patches","changes");
        require(n.path("schema").asInt()==1&&n.path("statePolicy").asText().equals("no-migrations"),"UNSUPPORTED_RELEASE_POLICY");
        text(n,"release","[A-Za-z0-9][A-Za-z0-9._+-]{0,79}");text(n,"sourceCommit","[a-f0-9]{40}");
        Instant created=Instant.parse(n.path("createdAt").asText()),expires=Instant.parse(n.path("expiresAt").asText());
        require(!created.isAfter(now)&&expires.isAfter(now)&&expires.isAfter(created),"RELEASE_EXPIRED_OR_FUTURE");
        require(n.path("patches").isObject()&&!n.path("patches").isEmpty(),"PATCH_INVENTORY_REQUIRED");
        for(var p:n.path("patches").properties())require(p.getKey().matches("containers/[A-Za-z0-9_./-]+")&&!p.getKey().contains("..")&&p.getValue().asText().matches(HASH),"INVALID_PATCH");
        require(n.path("changes").isArray()&&n.path("changes").size()>0&&n.path("changes").size()<=4,"INVALID_CHANGES");
        var services=new HashSet<String>();
        for(var c:n.path("changes")) {
            keys(c,"service","fromImage","toImage","fromVersion","toVersion","archive","archiveSha256","archiveBytes");
            String service=text(c,"service","app|tor|i2p|nym");require(services.add(service),"DUPLICATE_SERVICE");
            text(c,"fromImage",IMAGE);text(c,"toImage",IMAGE);require(!c.path("fromImage").equals(c.path("toImage")),"UNCHANGED_IMAGE");
            text(c,"fromVersion","[A-Za-z0-9][A-Za-z0-9._+~:-]{0,95}");text(c,"toVersion","[A-Za-z0-9][A-Za-z0-9._+~:-]{0,95}");
            text(c,"archiveSha256",HASH);require(c.path("archive").isTextual()&&c.path("archive").asText().length()<=2048,"INVALID_ARCHIVE");
            require(c.path("archiveBytes").isIntegralNumber()&&c.path("archiveBytes").asLong()>0,"INVALID_ARCHIVE_SIZE");
        }
        return new UpdateManifest(hash(bytes),n);
    }
    void fresh() {require(Instant.parse(document.path("expiresAt").asText()).isAfter(Instant.now()),"RELEASE_EXPIRED");}
}
