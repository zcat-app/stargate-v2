// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.function.Consumer;
import static app.zcat.stargate.updater.UpdateFiles.*;
import static org.junit.jupiter.api.Assertions.*;

class UpdatePolicyOrderingTest {
    @TempDir Path tmp;
    UpdateTest.Fixture fixture()throws Exception {
        var support=new UpdateTest();support.tmp=tmp;
        return support.fixture();
    }
    static ObjectNode policy(boolean reordered) {
        var p=JSON.createObjectNode();var host=p.putObject("HostConfig");
        host.put("Privileged",false);host.putArray("Binds").add("volume-a:/data:rw").add("volume-b:/control:ro");
        var mounts=host.putArray("Mounts");
        mounts.addObject().put("Type","bind").put("Source","/srv/example/public").put("Target","/public").put("ReadOnly",true).putObject("BindOptions");
        mounts.addObject().put("Type","bind").put("Source","/srv/example/inbox").put("Target","/inbox").put("ReadOnly",false).putObject("BindOptions");
        var config=p.putObject("Config");config.put("User","10001");
        config.putArray("Env").add("MODE=one").add("PATH=/usr/bin").add("VALUE=contains=equals");
        config.putArray("Cmd").add("java").add("Application");
        p.putArray("networks").add("network-a");
        if(reordered){reverse(config.withArray("Env"));reverse(mounts);reverse(host.withArray("Binds"));}
        return p;
    }
    static void reverse(ArrayNode a){var values=new ArrayList<JsonNode>();a.forEach(values::add);a.removeAll();values.reversed().forEach(a::add);}
    static class Ordered extends UpdateTest.Fake {
        boolean reorder;
        Ordered(UpdateTest.Fixture f)throws Exception{super(f.config,f.engine.commands);}
        @Override ObjectNode observe(){var n=super.observe();((ObjectNode)n.path("app")).set("policy",policy(reorder||image.equals(UpdateTest.NEW)));return n;}
    }
    @Test void reorderBeforeAndAfterReplacementAndRollbackDoesNotRewriteApproval()throws Exception {
        var f=fixture();var e=new Ordered(f);f.engine=e;e.refresh();String plan=e.state.path("plan").asText();
        byte[] before=JSON.writeValueAsBytes(e.state.path("before"));e.reorder=true;
        e.apply(plan,false);assertEquals("INSTALLED",e.state.path("phase").asText());
        e.apply(plan,true);assertEquals("ROLLED_BACK",e.state.path("phase").asText());
        assertEquals(plan,UpdateEngine.approvalHash(e.state));assertArrayEquals(before,JSON.writeValueAsBytes(e.state.path("before")));
    }
    @Test void legacyFailedJournalCanRollBackWithOriginalApprovedHash()throws Exception {
        var f=fixture();var first=new Ordered(f);f.engine=first;first.refresh();
        String plan=first.state.path("plan").asText();byte[] before=JSON.writeValueAsBytes(first.state.path("before"));
        first.state.put("phase","INSTALL_FAILED");first.save();
        var restarted=new Ordered(f);f.engine=restarted;restarted.image=UpdateTest.NEW;
        restarted.apply(plan,true);assertEquals("ROLLED_BACK",restarted.state.path("phase").asText());
        assertArrayEquals(before,JSON.writeValueAsBytes(restarted.state.path("before")));
        assertEquals(plan,UpdateEngine.approvalHash(restarted.state));
    }
    @Test void changedValuesMountOptionsAndOtherOrderedFieldsRemainDrift()throws Exception {
        var f=fixture();var e=new Ordered(f);f.engine=e;e.refresh();var m=e.saved(true);
        List<Consumer<ObjectNode>> changes=List.of(
                p->p.withObject("Config").withArray("Env").set(0,JSON.getNodeFactory().textNode("MODE=changed")),
                p->p.withObject("Config").withArray("Env").remove(0),
                p->((ObjectNode)p.path("HostConfig").path("Mounts").get(0)).put("Source","/srv/different"),
                p->((ObjectNode)p.path("HostConfig").path("Mounts").get(0)).put("Target","/different"),
                p->((ObjectNode)p.path("HostConfig").path("Mounts").get(0)).put("ReadOnly",false),
                p->((ObjectNode)p.path("HostConfig").path("Mounts").get(0)).withObject("BindOptions").put("Propagation","shared"),
                p->p.withObject("HostConfig").put("Privileged",true),
                p->reverse(p.withObject("Config").withArray("Cmd")),
                p->p.withArray("networks").add("network-b"));
        for(var change:changes){var current=e.observe();change.accept((ObjectNode)current.path("app").path("policy"));assertThrows(Exception.class,()->e.compatible(current,m,false));}
        assertTrue(f.calls.isEmpty(),"Policy drift must not invoke Docker mutation");
    }
    @Test void realDriftIsRejectedAtBothInstallObservations()throws Exception {
        for(int driftAt:List.of(1,2)) {
            Path previous=tmp;tmp=Files.createDirectory(tmp.resolve("observation-"+driftAt),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            var f=fixture();final int boundary=driftAt;
            var e=new Ordered(f) {
                boolean testing;int observations;
                @Override ObjectNode observe() {
                    var n=super.observe();
                    if(testing&&++observations==boundary)((ObjectNode)n.path("app").path("policy")).withObject("Config").withArray("Env").set(0,JSON.getNodeFactory().textNode("VALUE=changed"));
                    return n;
                }
            };
            f.engine=e;e.refresh();e.testing=true;e.reorder=true;
            String plan=e.state.path("plan").asText();
            var failure=assertThrows(IllegalArgumentException.class,()->e.apply(plan,false));
            assertEquals("DEPLOYMENT_CHANGED_REVIEW_AGAIN",failure.getMessage());
            assertFalse(f.calls.stream().anyMatch(c->c.contains("up")),"Drift must prevent service replacement");
            assertEquals(UpdateTest.OLD,e.image);tmp=previous;
        }
    }
    @Test void duplicateEnvironmentNamesAreRefusedEvenWhenBothRecordsMatch()throws Exception {
        for(String value:List.of("MODE=one","MODE=different")){
            Path dir=Files.createDirectory(tmp.resolve(UUID.randomUUID().toString()),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));Path previous=tmp;tmp=dir;
            var f=fixture();var e=new Ordered(f);f.engine=e;e.refresh();var m=e.saved(true);
            ((ObjectNode)e.state.path("before").path("app").path("policy")).withObject("Config").withArray("Env").add(value);
            var current=e.state.path("before").deepCopy();assertThrows(Exception.class,()->e.compatible(current,m,false));tmp=previous;
        }
    }
    @Test void duplicateMountTargetsAreRefusedEvenWhenBothRecordsMatch()throws Exception {
        for(boolean changed:List.of(false,true)){
            Path dir=Files.createDirectory(tmp.resolve(UUID.randomUUID().toString()),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));Path previous=tmp;tmp=dir;
            var f=fixture();var e=new Ordered(f);f.engine=e;e.refresh();var m=e.saved(true);
            var policy=(ObjectNode)e.state.path("before").path("app").path("policy");
            ObjectNode duplicate=policy.path("HostConfig").path("Mounts").get(0).deepCopy();if(changed)duplicate.put("ReadOnly",false);
            policy.withObject("HostConfig").withArray("Mounts").add(duplicate);
            var current=e.state.path("before").deepCopy();assertThrows(Exception.class,()->e.compatible(current,m,false));tmp=previous;
        }
    }
    static final List<String> DNS_FIELDS=List.of("Dns","DnsOptions","DnsSearch");
    static ObjectNode observation(ObjectNode policy) {
        var result=JSON.createObjectNode();result.putObject("app").set("policy",policy);return result;
    }
    @Test void explicitNullAndEmptyDnsDefaultsCompareEquallyWithoutChangingInputs()throws Exception {
        for(String field:DNS_FIELDS) {
            var recorded=observation(policy(false));recorded.withObject("app").withObject("policy").withObject("HostConfig").putNull(field);
            ObjectNode current=recorded.deepCopy();current.withObject("app").withObject("policy").withObject("HostConfig").putArray(field);
            byte[] recordedBytes=JSON.writeValueAsBytes(recorded),currentBytes=JSON.writeValueAsBytes(current);
            assertTrue(UpdateEngine.sameObservation(current,recorded),field);
            assertTrue(UpdateEngine.sameObservation(recorded,current),field);
            assertTrue(UpdateEngine.comparisonPolicy(recorded.path("app").path("policy")).path("HostConfig").path(field).isArray(),field);
            assertArrayEquals(recordedBytes,JSON.writeValueAsBytes(recorded),field);
            assertArrayEquals(currentBytes,JSON.writeValueAsBytes(current),field);
            assertTrue(recorded.path("app").path("policy").path("HostConfig").path(field).isNull(),field);
        }
    }
    @Test void missingDnsDefaultsStayMissingAndDifferFromPresentNullOrEmpty() {
        for(String field:DNS_FIELDS) {
            var missing=observation(policy(false));
            assertTrue(UpdateEngine.comparisonPolicy(missing.path("app").path("policy")).path("HostConfig").path(field).isMissingNode(),field);
            for(JsonNode value:List.<JsonNode>of(JSON.getNodeFactory().nullNode(),JSON.createArrayNode())) {
                ObjectNode present=missing.deepCopy();present.withObject("app").withObject("policy").withObject("HostConfig").set(field,value);
                assertFalse(UpdateEngine.sameObservation(missing,present),field);
                assertFalse(UpdateEngine.sameObservation(present,missing),field);
            }
        }
    }
    @Test void nonemptyDnsValuesAndTheirOrderRemainStrict()throws Exception {
        for(String field:DNS_FIELDS) {
            var recorded=observation(policy(false));
            recorded.withObject("app").withObject("policy").withObject("HostConfig").putArray(field).add("first").add("second");
            byte[] original=JSON.writeValueAsBytes(recorded);
            assertTrue(UpdateEngine.sameObservation(recorded,recorded.deepCopy()),field);
            List<Consumer<ObjectNode>> changes=List.of(
                    host->reverse(host.withArray(field)),
                    host->host.withArray(field).set(0,JSON.getNodeFactory().textNode("changed")),
                    host->host.withArray(field).remove(0),host->host.putNull(field),host->host.putArray(field));
            for(var change:changes) {
                ObjectNode current=recorded.deepCopy();change.accept(current.withObject("app").withObject("policy").withObject("HostConfig"));
                assertFalse(UpdateEngine.sameObservation(current,recorded),field);
                assertFalse(UpdateEngine.sameObservation(recorded,current),field);
            }
            assertArrayEquals(original,JSON.writeValueAsBytes(recorded),field);
        }
    }
    @Test void malformedDnsFieldsAreRefusedEvenWhenBothObservationsMatch()throws Exception {
        List<JsonNode> malformed=List.of(JSON.getNodeFactory().textNode("resolver"),JSON.getNodeFactory().numberNode(1),
                JSON.getNodeFactory().booleanNode(false),JSON.createObjectNode(),JSON.createArrayNode().add(1),
                JSON.createArrayNode().addNull(),JSON.createArrayNode().add(JSON.createObjectNode()));
        for(String field:DNS_FIELDS)for(JsonNode value:malformed) {
            var observation=observation(policy(false));observation.withObject("app").withObject("policy").withObject("HostConfig").set(field,value);
            byte[] original=JSON.writeValueAsBytes(observation);
            var failure=assertThrows(IllegalArgumentException.class,()->UpdateEngine.sameObservation(observation,observation.deepCopy()),field);
            assertEquals(value.isArray()?"INVALID_DNS_POLICY_ENTRY":"INVALID_DNS_POLICY",failure.getMessage(),field);
            assertArrayEquals(original,JSON.writeValueAsBytes(observation),field);
        }
    }
    @Test void dnsDefaultsDoNotConcealOtherPolicyDrift() {
        var recorded=observation(policy(false));var host=recorded.withObject("app").withObject("policy").withObject("HostConfig");
        DNS_FIELDS.forEach(host::putNull);host.putNull("CapAdd");
        List<Consumer<ObjectNode>> changes=List.of(
                p->p.withObject("HostConfig").putArray("CapAdd"),
                p->p.withObject("HostConfig").put("Privileged",true),
                p->reverse(p.withObject("Config").withArray("Cmd")),
                p->p.withArray("networks").add("different-network"));
        for(var change:changes) {
            ObjectNode current=recorded.deepCopy();var currentPolicy=current.withObject("app").withObject("policy");
            DNS_FIELDS.forEach(field->currentPolicy.withObject("HostConfig").putArray(field));
            assertTrue(UpdateEngine.sameObservation(current,recorded));
            change.accept(currentPolicy);assertFalse(UpdateEngine.sameObservation(current,recorded));
        }
    }
    static class DnsDefaults extends Ordered {
        boolean emptyDns;
        DnsDefaults(UpdateTest.Fixture fixture)throws Exception{super(fixture);}
        @Override ObjectNode observe() {
            var observed=super.observe();
            for(var service:observed.properties()) {
                var host=((ObjectNode)service.getValue().path("policy")).withObject("HostConfig");
                for(String field:DNS_FIELDS)if(emptyDns)host.putArray(field);else host.putNull(field);
            }
            return observed;
        }
    }
    @Test void dnsDefaultRepresentationChangesAllowInstallAndRollbackWithOriginalApproval()throws Exception {
        var f=fixture();var e=new DnsDefaults(f);f.engine=e;e.refresh();String plan=e.state.path("plan").asText();
        byte[] before=JSON.writeValueAsBytes(e.state.path("before"));e.emptyDns=true;
        e.apply(plan,false);assertEquals("INSTALLED",e.state.path("phase").asText());
        e.apply(plan,true);assertEquals("ROLLED_BACK",e.state.path("phase").asText());
        assertArrayEquals(before,JSON.writeValueAsBytes(e.state.path("before")));
        assertEquals(plan,UpdateEngine.approvalHash(e.state));
        assertEquals(2,f.calls.stream().filter(command->command.contains("up")).count());
    }
}
