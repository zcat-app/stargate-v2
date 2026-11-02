// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Path;
import java.time.*;
import java.util.*;

/** Private change ledger and outbox; durable state precedes external effects. */
final class MonitorLedger {
    static final List<String> NAMES=List.of("nym","i2pd","quarkus","temurin","netty","tor_package_metadata","age","advisories","quarkus_advisories","runtime_security");
    record Evidence(String checked,String fingerprint,ObjectNode entries) {}
    final Path path;
    final ObjectNode state;
    MonitorLedger(Path path) throws Exception {this.path=path;state=(ObjectNode)MonitorFiles.json(path,MonitorFiles.REPORT_LIMIT,true);validate(state);}
    static ObjectNode initial(long maxAge,Instant now) {
        var s=MonitorFiles.object();s.put("schema_version",1);s.put("epoch",UUID.randomUUID().toString().replace("-",""));s.put("sequence",0);s.put("last_now",now.toString());s.put("max_age_seconds",maxAge);s.putObject("checks");s.putObject("advisories");s.putObject("quarkus_advisories");s.putNull("pending");return s;
    }
    static boolean hash(JsonNode n) {return n.isTextual()&&n.asText().matches("[0-9a-f]{64}");}
    static Instant stamp(String value) {if(!value.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"))throw new IllegalArgumentException("invalid UTC stamp");return Instant.parse(value);}
    static void validate(ObjectNode s) throws Exception {
        if(s.path("schema_version").asInt()!=1||!s.path("epoch").asText().matches("[0-9a-f]{32}")||!s.path("sequence").isIntegralNumber()||!s.path("sequence").canConvertToLong()||s.path("sequence").asLong()<0||!s.path("max_age_seconds").isIntegralNumber()||!s.path("max_age_seconds").canConvertToLong()||s.path("max_age_seconds").asLong()<=0)throw new IllegalArgumentException("invalid ledger identity");
        Instant last=stamp(s.path("last_now").asText());
        if(!s.path("checks").isObject()||!s.path("advisories").isObject()||!s.path("quarkus_advisories").isObject()||!s.has("pending"))throw new IllegalArgumentException("invalid ledger schema");
        for(var entry:s.path("checks").properties()) {
            var c=entry.getValue();if(!NAMES.contains(entry.getKey())||!Set.of("observed","unknown").contains(c.path("health").asText())||!c.has("watermark")||!c.has("evidence")||!c.has("baseline"))throw new IllegalArgumentException("invalid retained check");
            boolean water=!c.path("watermark").isNull();if(water==c.path("evidence").isNull()||(!c.path("baseline").isNull()&&!water))throw new IllegalArgumentException("invalid retained evidence");
            if(water&&(stamp(c.path("watermark").asText()).isAfter(last)||!hash(c.path("evidence"))))throw new IllegalArgumentException("invalid check time or hash");
            if(!c.path("baseline").isNull()&&!hash(c.path("baseline")))throw new IllegalArgumentException("invalid baseline");
            if(c.path("health").asText().equals("observed")&&(c.path("baseline").isNull()||!c.path("evidence").asText().equals(proof(c.path("baseline").asText()))))throw new IllegalArgumentException("inconsistent observed check");
        }
        for(String name:List.of("advisories","quarkus_advisories"))for(var e:s.path(name).properties()) {
            if(!e.getKey().matches("GHSA-[a-z0-9-]+")||!hash(e.getValue().path("fingerprint"))||stamp(e.getValue().path("updated").asText()).isAfter(last)||s.path("checks").path(name).path("baseline").isNull()||!s.path("checks").has(name))throw new IllegalArgumentException("invalid retained advisory");
        }
        var p=s.path("pending");if(!p.isNull()&&(!p.isObject()||!p.path("event_id").asText().equals(s.path("epoch").asText()+"-"+s.path("sequence").asLong())||!p.path("text").isTextual()||p.path("text").asText().getBytes(java.nio.charset.StandardCharsets.UTF_8).length>4000||p.path("text").asText().isBlank()))throw new IllegalArgumentException("invalid pending event");
    }
    static String proof(String item) throws IOException {var a=MonitorFiles.JSON.createArrayNode();a.add(item==null?"unknown":"observed");if(item!=null)a.add(item);return MonitorFiles.fingerprint(a);}
    static boolean fresh(String time,Instant current,long age) {try{long seconds=Duration.between(stamp(time),current).getSeconds();return seconds>=0&&seconds<=age;}catch(Exception e){return false;}}
    static JsonNode releaseSelected(String name,JsonNode item) {
        return switch(name) {
            case "nym" -> item.required("latest_tag");
            case "i2pd" -> MonitorFiles.JSON.createArrayNode().add(item.required("latest_tag")).add(item.required("latest_published_at"));
            case "quarkus" -> MonitorFiles.JSON.createArrayNode().add(item.required("family")).add(item.required("greatest_numeric_version"));
            case "age" -> MonitorFiles.JSON.createArrayNode().add(item.required("selected_tag")).add(item.required("latest_tag"));
            case "temurin" -> MonitorFiles.JSON.createArrayNode().add(item.required("upstream").required("release_name")).add(item.required("upstream").required("openjdk_version"));
            case "netty" -> MonitorFiles.JSON.createArrayNode().add(item.required("sha256")).add(item.required("modules"));
            case "tor_package_metadata" -> {var result=MonitorFiles.object();for(var e:item.required("packages").properties())result.set(e.getKey(),e.getValue().required("published"));yield result;}
            default -> throw new IllegalArgumentException("unknown release check");
        };
    }
    static Map<String,Evidence> releases(JsonNode report) {
        var out=new HashMap<String,Evidence>();String completed=report.path("completed_at").asText();
        for(String name:NAMES.subList(0,7))try {
            stamp(completed);out.put(name,new Evidence(completed,null,null));
            var check=report.required("checks").required(name);if(!check.path("outcome").asText().equals("observed"))continue;
            var i=check.required("observation");String checked=switch(name){case "temurin"->i.required("observed_at_utc").asText();case "netty"->completed;default->i.required("checked_at").asText();};
            Instant observed=Instant.parse(checked);if(observed.isAfter(stamp(completed)))continue;
            if(name.equals("i2pd")&&Instant.parse(i.required("latest_published_at").asText()).isAfter(observed))continue;
            if(name.equals("quarkus")&&Instant.parse(i.required("metadata_last_updated").asText()).isAfter(observed))continue;
            out.put(name,new Evidence(observed.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString(),MonitorFiles.fingerprint(releaseSelected(name,i)),null));
        }catch(Exception ignored){}return out;
    }
    static Evidence advisory(JsonNode report) throws Exception {
        if(!report.path("status").asText().equals("observed")||!report.path("security_status").asText().equals("not_assessed")||!report.path("candidates").isArray())throw new IllegalArgumentException("advisories unknown");
        String checked=report.required("checked_at").asText();stamp(checked);var entries=MonitorFiles.object();var projection=MonitorFiles.object();
        for(var raw:report.path("candidates")) {
            var c=(ObjectNode)raw.deepCopy();String id=c.required("ghsa_id").asText(),updated=c.required("updated_at").asText();
            if(!id.matches("GHSA-[a-z0-9-]+")||entries.has(id)||stamp(updated).isAfter(stamp(checked)))throw new IllegalArgumentException("advisory chronology invalid");
            var packages=new ArrayList<JsonNode>();c.required("packages").forEach(packages::add);packages.sort(Comparator.comparing(MonitorLedger::canonicalText));var sorted=c.putArray("packages");packages.forEach(sorted::add);
            String fingerprint=MonitorFiles.fingerprint(c);var e=entries.putObject(id);e.put("fingerprint",fingerprint);e.put("updated",updated);projection.set(id,MonitorFiles.JSON.createArrayNode().add(fingerprint).add(updated));
        }
        return new Evidence(checked,MonitorFiles.fingerprint(projection),entries);
    }
    static String canonicalText(JsonNode n) {try{return MonitorFiles.JSON.writeValueAsString(MonitorFiles.canonical(n));}catch(Exception e){throw new IllegalArgumentException(e);}}
    static Evidence runtime(JsonNode report) throws Exception {
        if(!report.path("security_status").asText().equals("not_assessed")||!report.path("deployment_binding").path("status").asText().equals("observed")||!report.path("osv_observation").path("status").asText().equals("observed"))throw new IllegalArgumentException("runtime unknown");
        String checked=report.required("deployment_binding").required("checked_at").asText(),osv=report.required("osv_observation").required("checked_at").asText();if(Instant.parse(checked).isAfter(Instant.parse(osv)))throw new IllegalArgumentException("invalid binding chronology");
        var selected=MonitorFiles.object();for(var e:report.required("images").properties()) {
            var i=e.getValue();String image=i.required("image_id").asText();if(!image.matches("sha256:[0-9a-f]{64}")||!i.path("scan").path("source_binding").path("selected_image_id").asText().equals(image)||!hash(i.path("scan").path("source_binding").path("trivy_json_sha256")))throw new IllegalArgumentException("unbound scan");selected.put(e.getKey(),image);
        }
        var scopes=new ArrayList<JsonNode>();var entries=new ArrayList<JsonNode>();
        for(var q:report.required("osv_observation").required("queries")) {
            var roles=new TreeSet<String>();var types=new TreeSet<String>();for(var record:q.required("selected_records")) {
                String role=record.required("role").asText();if(!selected.path(role).equals(record.required("image_id")))throw new IllegalArgumentException("unbound OSV record");roles.add(role);types.add(record.required("evidence").asText());
            }
            var scope=MonitorFiles.JSON.createArrayNode().add(q.required("ecosystem")).add(q.required("name")).add(q.required("version"));scope.add(MonitorFiles.JSON.valueToTree(roles));scope.add(MonitorFiles.JSON.valueToTree(types));scopes.add(scope);
            for(var c:q.required("candidates")) {if(Instant.parse(c.required("modified").asText()).isAfter(Instant.parse(osv)))throw new IllegalArgumentException("future OSV advisory");var item=scope.deepCopy();item.remove(4);item.add(c.required("id"));item.add(c.required("modified"));entries.add(item);}
        }
        Comparator<JsonNode> cmp=Comparator.comparing(MonitorLedger::canonicalText);scopes.sort(cmp);entries.sort(cmp);
        var projection=MonitorFiles.JSON.createArrayNode().add(selected);projection.add(MonitorFiles.JSON.valueToTree(scopes));projection.add(MonitorFiles.JSON.valueToTree(entries));return new Evidence(Instant.parse(checked).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString(),MonitorFiles.fingerprint(projection),null);
    }
    void collect(JsonNode releases,JsonNode runtime,Instant current,long maxAge) throws Exception {
        validate(state);if(!state.path("pending").isNull())throw new IllegalStateException("pending event blocks fresh collection");
        if(current.isBefore(stamp(state.path("last_now").asText()))||state.path("max_age_seconds").asLong()!=maxAge)throw new IllegalArgumentException("clock or policy changed");
        var evidence=releases(releases);
        for(String name:List.of("advisories","quarkus_advisories"))try {evidence.put(name,advisory(releases.required("checks").required(name).required("observation")));}catch(Exception ignored){}
        try{evidence.put("runtime_security",runtime(runtime));}catch(Exception ignored){}
        var failed=new ArrayList<String>();var recovered=new ArrayList<String>();var changed=new ArrayList<String>();var checks=(ObjectNode)state.path("checks");
        int newNetty=0,changedNetty=0,newQuarkus=0,changedQuarkus=0;
        for(String name:NAMES) {
            var old=checks.path(name);String oldHealth=old.path("health").asText();String baseline=old.path("baseline").isTextual()?old.path("baseline").asText():null;
            Evidence e=evidence.get(name);boolean valid=e!=null&&fresh(e.checked,current,maxAge);boolean observed=valid&&e.fingerprint!=null;String proof=proof(observed?e.fingerprint:null);
            if(valid&&old.path("watermark").isTextual()) {int comparison=stamp(e.checked).compareTo(stamp(old.path("watermark").asText()));valid=comparison>0||(comparison==0&&oldHealth.equals("observed")&&old.path("evidence").asText().equals(proof));observed&=valid;}
            if(observed&&e.entries!=null) {
                var retained=(ObjectNode)state.path(name);int added=0,modified=0;
                for(var entry:e.entries.properties()) {var previous=retained.path(entry.getKey());if(!previous.isMissingNode()&&stamp(entry.getValue().path("updated").asText()).isBefore(stamp(previous.path("updated").asText()))){observed=false;valid=false;break;}if(previous.isMissingNode())added++;else if(!previous.path("fingerprint").equals(entry.getValue().path("fingerprint")))modified++;}
                if(observed) {if(baseline!=null){if(name.equals("advisories")){newNetty=added;changedNetty=modified;}else{newQuarkus=added;changedQuarkus=modified;}}e.entries.properties().forEach(entry->retained.set(entry.getKey(),entry.getValue()));}
            }
            if(observed) {if(oldHealth.equals("unknown"))recovered.add(name);if(e.entries==null&&baseline!=null&&!baseline.equals(e.fingerprint))changed.add(name);baseline=e.fingerprint;}else if(!oldHealth.equals("unknown"))failed.add(name);
            var c=old.isObject()?(ObjectNode)old.deepCopy():MonitorFiles.object();c.put("health",observed?"observed":"unknown");if(valid){c.put("watermark",e.checked);c.put("evidence",proof);}else{if(!c.has("watermark"))c.putNull("watermark");if(!c.has("evidence"))c.putNull("evidence");}c.put("baseline",baseline);checks.set(name,c);
        }
        state.put("last_now",current.toString());
        if(!failed.isEmpty()||!recovered.isEmpty()||!changed.isEmpty()||newNetty+changedNetty+newQuarkus+changedQuarkus>0){
            String text=MonitorAlert.render(new MonitorAlert.Event(failed,recovered,changed,newNetty,changedNetty,newQuarkus,changedQuarkus),releases);
            long sequence=Math.addExact(state.path("sequence").asLong(),1);state.put("sequence",sequence);var pending=state.putObject("pending");pending.put("event_id",state.path("epoch").asText()+"-"+sequence);pending.put("text",text);
        }save();
    }
    void save() throws Exception {validate(state);MonitorFiles.replace(path,state);}
    void acknowledge() throws Exception {state.putNull("pending");save();}
}
