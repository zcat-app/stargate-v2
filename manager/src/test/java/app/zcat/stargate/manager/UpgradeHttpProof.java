package app.zcat.stargate.manager;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.*;
import static org.junit.jupiter.api.Assertions.*;
/** Explicit opt-in after package: -Dtest=UpgradeHttpProof. Loopback fixture; no Docker access. */
class UpgradeHttpProof {
 @TempDir Path tmp;
 @Test void realQuarkusSessionOriginAndCsrfGateTheQueuedUpgrade()throws Exception {
  int port;try(var socket=new java.net.ServerSocket(0,0,InetAddress.getLoopbackAddress())){port=socket.getLocalPort();}
  String origin="http://127.0.0.1:"+port,token="a".repeat(43);Path proxy=tmp.resolve("proxy.properties"),config=tmp.resolve("manager.properties"),exchange=tmp.resolve("upgrade");Files.createDirectories(exchange.resolve("public"));Files.createDirectories(exchange.resolve("inbox"));
  for(var p:new Path[]{proxy,config})Files.createFile(p,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
  Files.writeString(proxy,"listen.port=8881\ntor.port=9050\n");Files.writeString(config,"manager.token="+token+"\nmanager.origin="+origin+"\nproxy.config="+proxy+"\ntor.control.port=9051\ntor.cookie="+tmp.resolve("cookie")+"\nupgrade.directory="+exchange+"\n");
  var json=new ObjectMapper();var status=json.createObjectNode().put("schema",1).put("phase","PREPARED").put("plan","b".repeat(64)).put("signer","c".repeat(64)).put("observedAt",Instant.now().toString());var release=status.putObject("release").put("release","HTTP-fixture").put("sourceCommit","d".repeat(40)).put("expiresAt",Instant.now().plusSeconds(3600).toString());release.putObject("patches").put("containers/fix.patch","e".repeat(64));release.putArray("changes").addObject().put("service","app").put("fromVersion","old").put("toVersion","new").put("fromImage","sha256:"+"1".repeat(64)).put("toImage","sha256:"+"2".repeat(64));Files.writeString(exchange.resolve("public/status.json"),json.writeValueAsString(status));
  Path log=tmp.resolve("manager.log");var p=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"-Dstargate.config="+config,"-Dquarkus.http.host=127.0.0.1","-Dquarkus.http.port="+port,"-jar",Path.of("target/quarkus-app/quarkus-run.jar").toAbsolutePath().toString()).redirectErrorStream(true).redirectOutput(log.toFile()).start();
  try(var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()){
   boolean ready=false;for(int i=0;i<60;i++){try{if(client.send(HttpRequest.newBuilder(URI.create(origin)).GET().build(),HttpResponse.BodyHandlers.ofString()).statusCode()==200){ready=true;break;}}catch(Exception ignored){}Thread.sleep(100);}assertTrue(ready,()->{try{return Files.readString(log);}catch(Exception e){return "no log";}});
   var login=client.send(HttpRequest.newBuilder(URI.create(origin+"/login")).header("Origin",origin).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString("token="+token)).build(),HttpResponse.BodyHandlers.ofString());assertEquals(303,login.statusCode());String cookie=login.headers().firstValue("set-cookie").orElseThrow().split(";")[0];
   status.put("observedAt",Instant.now().toString());Files.writeString(exchange.resolve("public/status.json"),json.writeValueAsString(status));
   var page=client.send(HttpRequest.newBuilder(URI.create(origin)).header("Cookie",cookie).GET().build(),HttpResponse.BodyHandlers.ofString());assertTrue(page.body().contains("Install reviewed upgrade"));String csrf=java.util.regex.Pattern.compile("name=\"csrf\" value=\"([A-Za-z0-9_-]{43})\"").matcher(page.body()).results().findFirst().orElseThrow().group(1);
   for(String[] attempt:new String[][]{{"https://attacker.invalid",csrf,"403"},{origin,"wrong","403"},{origin,csrf,"200"}}){var response=client.send(HttpRequest.newBuilder(URI.create(origin+"/upgrades/install")).header("Origin",attempt[0]).header("Cookie",cookie).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString("csrf="+attempt[1]+"&plan="+"b".repeat(64))).build(),HttpResponse.BodyHandlers.ofString());assertEquals(Integer.parseInt(attempt[2]),response.statusCode());if(!attempt[2].equals("200"))assertFalse(Files.exists(exchange.resolve("inbox/request.json")));}
   var request=json.readTree(Files.readString(exchange.resolve("inbox/request.json")));assertEquals("install",request.path("action").asText());assertEquals("b".repeat(64),request.path("plan").asText());System.out.println("UPGRADE_HTTP_PROOF PASS real Quarkus session/origin/CSRF and queue");
  }finally{p.destroy();if(!p.waitFor(5,java.util.concurrent.TimeUnit.SECONDS))p.destroyForcibly().waitFor();}
 }
}
