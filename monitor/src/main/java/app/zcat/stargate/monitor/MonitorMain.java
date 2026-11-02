// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;

/** Host operator one-shot. The manager only reads the sanitized snapshots. */
public final class MonitorMain {
    record Config(Path source,Path recorder,Path output,Path ledger,Path dispatch,Path profile,String contact,
                  Path nettyJar,String family,String temurin,String age,Path selection,Path containers,
                  Path dispositions,long securityMaxAge,long ledgerMaxAge) {
        static Config read(Path path) throws Exception {
            var v=MonitorFiles.json(path,16384,true);
            var keys=Set.of("schema_version","source_root","recorder","output","ledger","dispatch","profile","contact_id","netty_jar","quarkus_family","temurin_deployment_build","age_tag","security_selection","security_runtime_containers","security_dispositions","security_max_age_seconds","ledger_max_age_seconds");
            if(!v.isObject()||!v.properties().stream().map(Map.Entry::getKey).collect(java.util.stream.Collectors.toSet()).equals(keys)||v.path("schema_version").asInt()!=1)throw new IllegalArgumentException("invalid monitor configuration");
            var c=new Config(p(v,"source_root"),p(v,"recorder"),p(v,"output"),p(v,"ledger"),p(v,"dispatch"),p(v,"profile"),s(v,"contact_id"),p(v,"netty_jar"),s(v,"quarkus_family"),s(v,"temurin_deployment_build"),s(v,"age_tag"),p(v,"security_selection"),p(v,"security_runtime_containers"),p(v,"security_dispositions"),positive(v,"security_max_age_seconds"),positive(v,"ledger_max_age_seconds"));
            if(!c.contact.matches("[1-9][0-9]{0,18}")||Long.parseLong(c.contact)<=0||!c.family.matches("[0-9]+\\.[0-9]+")||!c.temurin.matches("[0-9]+(?:\\.[0-9]+)*\\+[0-9]+")||!c.age.matches("v[0-9]+\\.[0-9]+\\.[0-9]+"))throw new IllegalArgumentException("invalid monitor selection");
            for(Path d:List.of(c.recorder,c.ledger,c.dispatch))MonitorFiles.directory(d,true);
            MonitorFiles.directory(c.source,false);MonitorFiles.directory(c.output,false);
            if((((Number)MonitorFiles.attribute(c.output,"mode")).intValue()&07777)!=0755||((Number)MonitorFiles.attribute(c.output,"uid")).intValue()!=MonitorFiles.UID)throw new IllegalArgumentException("snapshot directory must be owned 0755");
            var separate=List.of(c.recorder,c.output,c.ledger,c.dispatch,c.profile);
            for(int i=0;i<separate.size();i++)for(int j=i+1;j<separate.size();j++)if(separate.get(i).startsWith(separate.get(j))||separate.get(j).startsWith(separate.get(i)))throw new IllegalArgumentException("operational directories overlap");
            MonitorSender.profile(c.profile);var identities=new HashSet<String>();for(Path d:separate)if(!identities.add(MonitorFiles.attribute(d,"dev")+":"+MonitorFiles.attribute(d,"ino")))throw new IllegalArgumentException("operational directory aliases refused");return c;
        }
        static String s(JsonNode v,String key) {if(!v.path(key).isTextual()||v.path(key).asText().isBlank())throw new IllegalArgumentException("missing configuration");return v.path(key).asText();}
        static Path p(JsonNode v,String key) {Path p=Path.of(s(v,key));if(!p.isAbsolute()||!p.equals(p.normalize()))throw new IllegalArgumentException("normalized absolute paths required");return p;}
        static long positive(JsonNode v,String key) {if(!v.path(key).isIntegralNumber()||!v.path(key).canConvertToLong()||v.path(key).asLong()<=0)throw new IllegalArgumentException("positive configuration value required");return v.path(key).asLong();}
    }
    static Instant now() {return Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);}
    static void snapshot(Config c,String latest,String attempt) throws Exception {
        var v=MonitorFiles.object();v.put("schema_version",1);v.put("published_at",MonitorFiles.now());v.put("latest",latest);v.put("attempt_at",attempt);MonitorFiles.publish(c.output.resolve("snapshot.json"),v);
    }
    static void consumer(Config c,String outcome,String attempt,String acceptance,Boolean blocked) throws Exception {
        var v=MonitorFiles.object();v.put("schema_version",1);v.put("published_at",MonitorFiles.now());v.put("attempt_at",attempt);v.put("outcome",outcome);v.put("local_acceptance",acceptance);if(blocked==null)v.putNull("future_collection_blocked");else v.put("future_collection_blocked",blocked);MonitorFiles.publish(c.output.resolve("consumer-snapshot.json"),v);
    }
    interface Collection {List<ObjectNode> collect(Config c) throws Exception;}
    static String dispatch(Config c,MonitorLedger ledger,MonitorSender.Send send) throws Exception {
        var pending=ledger.state.required("pending");String token=MonitorSender.dispatch(c.dispatch,pending.required("event_id").asText(),pending.required("text").asText(),send);
        if(token.equals("ACCEPTED")||token.equals("RECOVERED_ACCEPTED"))ledger.acknowledge();return token;
    }
    static int run(Config c) throws Exception {
        return run(c,MonitorMain::collect,body->MonitorSender.send(c.source,c.profile,c.contact,body));
    }
    static int run(Config c,Collection collect,MonitorSender.Send send) throws Exception {
        String started=MonitorFiles.now();
        try {
            consumer(c,"incomplete",started,"unknown",null);
            var ledger=new MonitorLedger(c.ledger.resolve("state.json"));
            if(!ledger.state.path("pending").isNull()) {
                String token=dispatch(c,ledger,send);boolean accepted=token.equals("ACCEPTED")||token.equals("RECOVERED_ACCEPTED");consumer(c,accepted?"fresh_observation_required":"blocked_uncertain",started,accepted?"accepted":"unknown",!accepted);return 4;
            }
            snapshot(c,"pending",started);consumer(c,"incomplete",started,"unknown",null);
            var reports=collect.collect(c);Instant completed=now();
            ledger.collect(reports.get(0),reports.get(1),completed,c.ledgerMaxAge);
            boolean complete=complete(reports.get(0),reports.get(1));
            snapshot(c,complete?"observed":"unknown",complete?reports.get(0).path("completed_at").asText():null);
            if(ledger.state.path("pending").isNull()) {consumer(c,complete?"quiet":"collection_unknown",started,"not_attempted",false);return complete?0:2;}
            String token=dispatch(c,ledger,send);boolean accepted=token.equals("ACCEPTED")||token.equals("RECOVERED_ACCEPTED");consumer(c,accepted?(complete?"locally_accepted":"collection_unknown"):"blocked_uncertain",started,accepted?"accepted":"unknown",!accepted);return accepted?(complete?0:2):4;
        }catch(Exception e){snapshot(c,"unknown",null);consumer(c,"unknown",started,"unknown",null);throw e;}
    }
    static boolean complete(JsonNode releases,JsonNode runtime) {
        if(!releases.path("outcome").asText().equals("observed"))return false;
        for(String name:MonitorLedger.NAMES.subList(0,9))if(!releases.path("checks").path(name).path("outcome").asText().equals("observed"))return false;
        try{MonitorLedger.runtime(runtime);return true;}catch(Exception e){return false;}
    }
    static List<ObjectNode> collect(Config c) throws Exception {
        var releases=ReleaseCollectors.collect(c.source,c.nettyJar,c.family,c.temurin,c.age,now());
        MonitorFiles.replace(c.recorder.resolve("latest-report.json"),releases);
        ObjectNode security;
        try {security=RuntimeSecurity.collect(c.selection,c.containers,c.dispositions,c.securityMaxAge,now(),c.recorder,c.source);RuntimeContext.enrich(security,releases,c.source);var bindingTime=Instant.parse(security.required("deployment_binding").required("checked_at").asText());var elapsed=java.time.Duration.between(bindingTime,Instant.now());if(elapsed.isNegative()||elapsed.compareTo(java.time.Duration.ofSeconds(c.securityMaxAge))>0)throw new IllegalStateException("runtime identity stale after context collection");MonitorFiles.replace(c.recorder.resolve("latest-security-binding.json"),security);}
        catch(Exception e){security=MonitorFiles.object();security.put("schema_version",1);security.put("status","unknown");security.put("security_status","not_assessed");MonitorFiles.replace(c.recorder.resolve("latest-security-binding.json"),security);}
        return List.of(releases,security);
    }
    public static void main(String[] args) {
        int code=4;
        try {
            if(args.length<3||!args[1].equals("--config"))throw new IllegalArgumentException("usage: run|collect|init|import --config ABSOLUTE_JSON [LEGACY_LEDGER LEGACY_BRIDGE]");
            Config c=Config.read(Path.of(args[2]));Path lock=c.ledger.resolve("java-monitor.lock");
            try(var channel=FileChannel.open(lock,Set.of(StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
                MonitorFiles.read(lock,64,true);
                try(var held=channel.tryLock()) {
                    if(held==null)throw new IllegalStateException("monitor busy");
                    switch(args[0]) {
                        case "run" -> {if(args.length!=3)throw new IllegalArgumentException();code=run(c);}
                        case "collect" -> {if(args.length!=3)throw new IllegalArgumentException();var reports=collect(c);code=complete(reports.get(0),reports.get(1))?0:2;}
                        case "init" -> {if(args.length!=3)throw new IllegalArgumentException();MonitorFiles.create(c.ledger.resolve("state.json"),MonitorFiles.bytes(MonitorLedger.initial(c.ledgerMaxAge,now())));code=0;}
                        case "import" -> {if(args.length!=5)throw new IllegalArgumentException();try(var consumerLock=new LegacyLock(c.recorder.resolve("alert-consumer.lock"),false);var dailyLock=new LegacyLock(c.recorder.resolve("daily.lock"),false)){var imported=LegacyImport.read(Path.of(args[3]),Path.of(args[4]),c.dispatch);MonitorLedger.validate(imported);if(imported.path("max_age_seconds").asLong()!=c.ledgerMaxAge)throw new IllegalArgumentException("legacy policy differs");MonitorFiles.create(c.ledger.resolve("state.json"),MonitorFiles.bytes(imported));code=0;}}
                        default -> throw new IllegalArgumentException("unknown monitor operation");
                    }
                }
            }
            System.out.println("{\"schema_version\":1,\"status\":\""+(code==0?"completed":"attention_required")+"\",\"phone_delivery\":\"unknown\"}");
        }catch(Exception e){System.err.println("Monitor refused or incomplete; inspect private evidence and operator guide. No automatic alert retry.");}
        System.exit(code);
    }
}
