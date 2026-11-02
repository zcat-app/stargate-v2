package app.zcat.stargate.manager;
import com.fasterxml.jackson.databind.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;
class UpgradeControlTest {
 @TempDir Path tmp;
 final ObjectMapper json=new ObjectMapper();
 com.fasterxml.jackson.databind.node.ObjectNode status()throws Exception {
  Files.createDirectories(tmp.resolve("public"));Files.createDirectories(tmp.resolve("inbox"));var n=json.createObjectNode().put("schema",1).put("phase","PREPARED").put("plan","a".repeat(64)).put("signer","b".repeat(64)).put("observedAt",Instant.now().toString());
  var r=n.putObject("release").put("release","test<escape>").put("sourceCommit","c".repeat(40)).put("expiresAt",Instant.now().plusSeconds(100).toString());r.putObject("patches").put("containers/fix.patch","d".repeat(64));r.putArray("changes").addObject().put("service","app").put("fromVersion","1").put("toVersion","2").put("fromImage","sha256:"+"1".repeat(64)).put("toImage","sha256:"+"2".repeat(64));publish(n);return n;
 }
 void publish(JsonNode n)throws Exception{Files.writeString(tmp.resolve("public/status.json"),json.writeValueAsString(n));}
 @Test void previewIsEscapedAndQueueBindsFreshPlanWithReadableAtomicRequest()throws Exception {
  status();var c=new UpgradeControl(tmp);var session=new WebSessions(java.time.Clock.systemUTC()).create();String h=c.html(session);assertTrue(h.contains("test&lt;escape&gt;"));assertTrue(h.contains("Install reviewed upgrade"));assertTrue(h.contains(session.csrf()));assertFalse(c.request("install","0".repeat(64)));assertTrue(c.request("install","a".repeat(64)));assertFalse(c.request("install","a".repeat(64)));
  var r=json.readTree(Files.readString(tmp.resolve("inbox/request.json")));assertEquals(2,r.size());assertEquals("install",r.path("action").asText());assertEquals("a".repeat(64),r.path("plan").asText());assertTrue(Files.getPosixFilePermissions(tmp.resolve("inbox/request.json")).contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ));
 }
 @Test void staleExpiredMissingAndUncertainStatesOfferNoInstall()throws Exception {
  var n=status();var c=new UpgradeControl(tmp);n.put("observedAt",Instant.now().minusSeconds(20).toString());publish(n);assertNull(c.observation());assertFalse(c.request("refresh",""));n.put("observedAt",Instant.now().toString());((com.fasterxml.jackson.databind.node.ObjectNode)n.path("release")).put("expiresAt",Instant.now().minusSeconds(1).toString());publish(n);assertFalse(c.request("install","a".repeat(64)));
  n.put("phase","UNCERTAIN");publish(n);assertFalse(c.request("rollback","a".repeat(64)));assertFalse(c.request("refresh",""));assertFalse(c.html(new WebSessions(java.time.Clock.systemUTC()).create()).contains("<button"));assertEquals("",new UpgradeControl(null).html(null));
 }
}
