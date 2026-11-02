// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;
import static app.zcat.stargate.updater.UpdateFiles.*;

/** Host-only authority. Web requests cannot supply URLs, keys, paths, services or commands. */
class UpdateEngine {
    interface Commands {String run(List<String> args,int seconds)throws Exception;}
    final JsonNode config;
    final Path root,publicDir,inbox;
    final Commands commands;
    ObjectNode state;
    UpdateEngine(Path file,Commands commands)throws Exception {
        privateFile(file);config=json(file);keys(config,"workDirectory","composeFile","project","releaseUrl","publicKeyFile","publicKeySha256","sourceDirectory","patches","preserve","maxArchiveBytes","localArtifactDirectory","waitSeconds","dockerSocket");
        text(config,"project","[a-z0-9][a-z0-9_-]{0,62}");text(config,"publicKeySha256",HASH);
        for(String field:List.of("workDirectory","composeFile","publicKeyFile","sourceDirectory"))require(Path.of(config.path(field).asText()).isAbsolute(),"ABSOLUTE_PATH_REQUIRED");
        privateFile(Path.of(config.path("composeFile").asText()));
        require(config.path("patches").isObject()&&!config.path("patches").isEmpty(),"PATCH_POLICY_REQUIRED");
        require(config.path("preserve").isObject(),"RUNTIME_PRESERVATION_POLICY_REQUIRED");
        require(config.path("maxArchiveBytes").isIntegralNumber()&&config.path("maxArchiveBytes").asLong()>0&&config.path("maxArchiveBytes").asLong()<=16L*1024*1024*1024,"INVALID_ARCHIVE_LIMIT");
        require(config.path("waitSeconds").asInt()>=10&&config.path("waitSeconds").asInt()<=600,"INVALID_WAIT");
        root=Path.of(config.path("workDirectory").asText()).normalize();directory(root,"rwx------");
        publicDir=root.resolve("public");inbox=root.resolve("inbox");directory(publicDir,"rwxr-xr-x");directory(inbox,"rwx-wx-wx");
        this.commands=commands;
        state=Files.exists(root.resolve("state.json"),NOFOLLOW_LINKS)?(ObjectNode)json(root.resolve("state.json")):JSON.createObjectNode().put("phase","EMPTY");
        if(state.has("configHash"))require(state.path("configHash").asText().equals(hash(file)),"UPDATER_CONFIGURATION_CHANGED");
        configHash=hash(file);
        Path claimed=root.resolve("claimed-request.json");
        if(Files.exists(claimed,NOFOLLOW_LINKS)) {
            Files.move(claimed,root.resolve("interrupted-request-"+UUID.randomUUID()+".json"),StandardCopyOption.ATOMIC_MOVE);
            if(state.path("phase").asText().equals("PREPARED"))state.put("phase","REVIEW_REQUIRED");
            state.put("error","INTERRUPTED_REQUEST_REQUIRES_REVIEW");save();
        }
    }
    final String configHash;
    List<String> compose(Path override,String... args) {
        var c=new ArrayList<>(List.of("compose","--project-name",config.path("project").asText(),"--file",config.path("composeFile").asText()));
        if(override!=null)c.addAll(List.of("--file",override.toString()));c.addAll(List.of(args));return c;
    }
    String docker(String... args)throws Exception{return commands.run(List.of(args),120);}
    JsonNode render()throws Exception{return JSON.readTree(commands.run(compose(null,"config","--format","json"),60));}
    ObjectNode observe()throws Exception {
        var result=JSON.createObjectNode();
        for(String service:new TreeSet<>(SERVICES)) {
            String id=commands.run(compose(null,"ps","--all","--quiet",service),60).trim();
            require(id.matches("[a-f0-9]{64}"),"ONE_EXISTING_CONTAINER_REQUIRED");
            JsonNode n=JSON.readTree(docker("inspect",id)).get(0);
            require(n.path("Config").path("Labels").path("com.docker.compose.project").asText().equals(config.path("project").asText())&&n.path("Config").path("Labels").path("com.docker.compose.service").asText().equals(service),"CONTAINER_BINDING_MISMATCH");
            var s=result.putObject(service);s.put("id",id);s.put("image",n.path("Image").asText());s.put("running",n.path("State").path("Running").asBoolean());
            s.put("composeHash",n.path("Config").path("Labels").path("com.docker.compose.config-hash").asText());
            var mounts=JSON.createArrayNode();n.path("Mounts").valueStream().sorted(Comparator.comparing(m->m.path("Destination").asText())).forEach(mounts::add);s.set("mounts",mounts);
            var selected=JSON.createObjectNode();selected.set("HostConfig",normalizedHost(n.path("HostConfig")));
            // Addresses and endpoint IDs change on recreation; retain the exact network names.
            var networks=JSON.createArrayNode();new TreeSet<>(n.path("NetworkSettings").path("Networks").properties().stream().map(Map.Entry::getKey).toList()).forEach(networks::add);selected.set("networks",networks);
            var containerConfig=(ObjectNode)n.path("Config").deepCopy();containerConfig.remove(List.of("Image","Hostname","Labels"));selected.set("Config",containerConfig);s.set("policy",selected);
            if(n.path("State").path("Health").isObject())s.put("health",n.path("State").path("Health").path("Status").asText());
        }
        return result;
    }
    static JsonNode normalizedHost(JsonNode host) {
        ObjectNode normalized=host.deepCopy();
        // Docker/Compose emits this set in nondeterministic order. Preserve each complete
        // source:destination:mode value; actual resolved Mounts are independently compared.
        if(normalized.path("Binds").isArray()) {var binds=JSON.createArrayNode();normalized.path("Binds").valueStream().map(JsonNode::asText).sorted().forEach(binds::add);normalized.set("Binds",binds);}
        return normalized;
    }
    // Compare copies only: historical before/rendered values are part of the
    // approved hash and must never be rewritten to canonicalize an old journal.
    static ObjectNode comparisonPolicy(JsonNode policy) {
        require(policy.isObject(),"INVALID_RUNTIME_POLICY");
        ObjectNode result=policy.deepCopy();
        if(result.hasNonNull("Config")) {
            require(result.path("Config").isObject(),"INVALID_CONTAINER_CONFIG");
            ObjectNode config=(ObjectNode)result.path("Config");
            if(config.hasNonNull("Env")) {
                require(config.path("Env").isArray(),"INVALID_ENVIRONMENT");
                var entries=new TreeMap<String,JsonNode>();
                for(var entry:config.path("Env")) {
                    require(entry.isTextual(),"INVALID_ENVIRONMENT_ENTRY");
                    String value=entry.asText();int equals=value.indexOf('=');
                    String name=equals<0?value:value.substring(0,equals);
                    require(!name.isEmpty()&&value.indexOf('\0')<0,"INVALID_ENVIRONMENT_ENTRY");
                    require(entries.putIfAbsent(name,entry)==null,"AMBIGUOUS_ENVIRONMENT_KEY");
                }
                var sorted=JSON.createArrayNode();entries.values().forEach(sorted::add);config.set("Env",sorted);
            }
        }
        if(result.hasNonNull("HostConfig")) {
            require(result.path("HostConfig").isObject(),"INVALID_HOST_CONFIG");
            JsonNode original=result.path("HostConfig");
            if(original.hasNonNull("Binds")) {
                require(original.path("Binds").isArray(),"INVALID_BINDINGS");
                for(var bind:original.path("Binds"))require(bind.isTextual(),"INVALID_BINDING");
            }
            ObjectNode host=(ObjectNode)normalizedHost(original);
            // Docker can represent unset DNS lists as explicit null or []. Normalize
            // only those present defaults on this comparison copy; preserve real order.
            for(String field:List.of("Dns","DnsOptions","DnsSearch")) {
                if(!host.has(field))continue;
                JsonNode value=host.get(field);
                require(value.isNull()||value.isArray(),"INVALID_DNS_POLICY");
                if(value.isNull())host.set(field,JSON.createArrayNode());
                else for(var entry:value)require(entry.isTextual(),"INVALID_DNS_POLICY_ENTRY");
            }
            if(host.hasNonNull("Mounts")) {
                require(host.path("Mounts").isArray(),"INVALID_MOUNTS");
                var entries=new TreeMap<String,JsonNode>();
                for(var mount:host.path("Mounts")) {
                    require(mount.isObject()&&mount.path("Target").isTextual()&&mount.path("Target").asText().startsWith("/"),"INVALID_MOUNT_TARGET");
                    require(entries.putIfAbsent(mount.path("Target").asText(),mount)==null,"AMBIGUOUS_MOUNT_TARGET");
                }
                var sorted=JSON.createArrayNode();entries.values().forEach(sorted::add);host.set("Mounts",sorted);
            }
            result.set("HostConfig",host);
        }
        return result;
    }
    static JsonNode comparisonObservation(JsonNode observation) {
        require(observation.isObject(),"INVALID_RUNTIME_OBSERVATION");
        ObjectNode result=observation.deepCopy();
        for(var service:result.properties()) {
            require(service.getValue().isObject(),"INVALID_RUNTIME_OBSERVATION");
            ObjectNode value=(ObjectNode)service.getValue();
            value.set("policy",comparisonPolicy(value.path("policy")));
        }
        return result;
    }
    static boolean sameObservation(JsonNode current,JsonNode recorded) {
        return comparisonObservation(current).equals(comparisonObservation(recorded));
    }
    void patches(UpdateManifest release)throws Exception {
        require(release.document().path("patches").equals(config.path("patches")),"PATCH_POLICY_CHANGED");
        Path source=Path.of(config.path("sourceDirectory").asText()).toRealPath();
        for(var p:config.path("patches").properties()) {
            require(p.getKey().matches("containers/[A-Za-z0-9_./-]+")&&!p.getKey().contains(".."),"INVALID_PATCH_PATH");
            Path f=source.resolve(p.getKey());require(f.toRealPath().startsWith(source)&&hash(f).equals(p.getValue().asText()),"LOCAL_PATCH_CHANGED");
        }
    }
    UpdateManifest saved(boolean expiry)throws Exception {
        Path release=releaseDirectory();
        var m=UpdateManifest.verify(read(release.resolve("release.json"),65536),read(release.resolve("release.sig"),64),read(Path.of(config.path("publicKeyFile").asText()),1024),config.path("publicKeySha256").asText(),expiry?Instant.now():Instant.parse(state.path("verifiedAt").asText()));
        require(m.id().equals(state.path("releaseId").asText())&&approvalHash(state).equals(state.path("plan").asText()),"PLAN_CHANGED");patches(m);return m;
    }
    Path releaseDirectory(){String id=text(state,"releaseId",HASH);return root.resolve("releases").resolve(id);}
    static String approvalHash(JsonNode state)throws Exception {
        var binding=JSON.createObjectNode();for(String k:List.of("releaseId","generation","configHash","before","rendered","previousOverride"))binding.set(k,state.required(k));return hash(JSON.writeValueAsBytes(binding));
    }
    void refresh()throws Exception {
        require(Set.of("EMPTY","PREPARED","ROLLED_BACK","INSTALLED","REVIEW_REQUIRED").contains(state.path("phase").asText()),"FINISH_CURRENT_TRANSACTION_FIRST");
        byte[] bytes=fetchSmall(config.path("releaseUrl").asText(),65536),sig=fetchSmall(config.path("releaseUrl").asText()+".sig",64);
        var m=UpdateManifest.verify(bytes,sig,read(Path.of(config.path("publicKeyFile").asText()),1024),config.path("publicKeySha256").asText(),Instant.now());patches(m);
        var rendered=render();require(rendered.path("services").isObject()&&rendered.path("services").properties().stream().map(Map.Entry::getKey).collect(java.util.stream.Collectors.toSet()).equals(SERVICES),"FOUR_SERVICE_CONFIGURATION_REQUIRED");
        var before=observe();configurationMatches(before);for(var service:before.properties())require(service.getValue().path("running").asBoolean(),"ALL_SERVICES_MUST_BE_RUNNING");
        for(var c:m.document().path("changes")) {
            String service=c.path("service").asText();require(before.path(service).path("image").equals(c.path("fromImage")),"CURRENT_IMAGE_CHANGED");
            require(c.path("archiveBytes").asLong()<=config.path("maxArchiveBytes").asLong(),"ARCHIVE_EXCEEDS_OPERATOR_LIMIT");
            require(config.path("preserve").path(service).isObject()&&!config.path("preserve").path(service).isEmpty(),"RUNTIME_PRESERVATION_POLICY_REQUIRED");
        }
        // Preview verifies release authority and binds current state, but does not load images or replace services.
        if(state.has("plan")) {
            Path history=root.resolve("history");directory(history,"rwx------");Path previous=history.resolve(state.path("plan").asText());directory(previous,"rwx------");
            write(previous.resolve("state.json"),state,false);
        }
        Path releases=root.resolve("releases");directory(releases,"rwx------");Path release=releases.resolve(m.id());
        if(Files.exists(release,NOFOLLOW_LINKS))require(Arrays.equals(read(release.resolve("release.json"),65536),bytes)&&Arrays.equals(read(release.resolve("release.sig"),64),sig),"IMMUTABLE_RELEASE_CHANGED");
        else {
            Path staging=releases.resolve(".candidate-"+UUID.randomUUID());directory(staging,"rwx------");
            try {write(staging.resolve("release.json"),bytes,false);write(staging.resolve("release.sig"),sig,false);Files.move(staging,release,StandardCopyOption.ATOMIC_MOVE);sync(releases);}
            finally {if(Files.exists(staging,NOFOLLOW_LINKS)){Files.deleteIfExists(staging.resolve("release.json"));Files.deleteIfExists(staging.resolve("release.sig"));Files.delete(staging);}}
        }
        var previousOverride=Files.exists(root.resolve("active.compose.json"),NOFOLLOW_LINKS)?json(root.resolve("active.compose.json")):JSON.createObjectNode().set("services",JSON.createObjectNode());
        state=JSON.createObjectNode().put("phase","PREPARED").put("releaseId",m.id()).put("generation",UUID.randomUUID().toString()).put("verifiedAt",Instant.now().toString()).put("configHash",configHash);state.set("before",before);state.set("rendered",rendered);state.set("previousOverride",previousOverride);state.put("plan",approvalHash(state));
        save();publish(null);
    }
    void stable()throws Exception {require(render().equals(state.path("rendered")),"COMPOSE_CONFIGURATION_CHANGED");}
    void configurationMatches(JsonNode observed)throws Exception {
        Path active=Files.exists(root.resolve("active.compose.json"),NOFOLLOW_LINKS)?root.resolve("active.compose.json"):null;
        String output=commands.run(compose(active,"config","--hash","*"),60);var hashes=new HashMap<String,String>();
        for(String line:output.strip().split("\\R")){String[] fields=line.strip().split("\\s+");require(fields.length==2&&SERVICES.contains(fields[0])&&fields[1].matches(HASH),"INVALID_COMPOSE_HASH");require(hashes.put(fields[0],fields[1])==null,"DUPLICATE_COMPOSE_HASH");}
        require(hashes.keySet().equals(SERVICES),"CONFIGURATION_SERVICE_MISMATCH");
        for(String service:SERVICES)require(observed.path(service).path("composeHash").asText().equals(hashes.get(service)),"CONFIGURATION_NOT_DEPLOYED");
        JsonNode rendered=render();
        for(String service:SERVICES)resourcePolicy(rendered.path("services").path(service),observed.path(service).path("policy").path("HostConfig"));
    }
    static void resourcePolicy(JsonNode service,JsonNode host) {
        require(!service.has("deploy"),"DEPLOY_RESOURCE_POLICY_UNSUPPORTED");
        var fields=Map.ofEntries(Map.entry("mem_limit","Memory"),Map.entry("mem_reservation","MemoryReservation"),Map.entry("cpu_period","CpuPeriod"),Map.entry("cpu_quota","CpuQuota"),Map.entry("cpu_rt_period","CpuRealtimePeriod"),Map.entry("cpu_rt_runtime","CpuRealtimeRuntime"),Map.entry("cpu_shares","CpuShares"));
        fields.forEach((compose,docker)->require(service.path(compose).asLong()==host.path(docker).asLong(),"LIVE_RESOURCE_POLICY_DIFFERS"));
        long memory=service.path("mem_limit").asLong(),swap=service.path("memswap_limit").asLong();if(swap==0&&memory>0)swap=Math.multiplyExact(memory,2);
        require(swap==host.path("MemorySwap").asLong(),"LIVE_RESOURCE_POLICY_DIFFERS");
        require(Math.max(0,service.path("pids_limit").asLong())==Math.max(0,host.path("PidsLimit").asLong()),"LIVE_RESOURCE_POLICY_DIFFERS");
        require(new java.math.BigDecimal(service.path("cpus").asText("0")).multiply(java.math.BigDecimal.valueOf(1000000000)).longValueExact()==host.path("NanoCpus").asLong(),"LIVE_RESOURCE_POLICY_DIFFERS");
        require(service.path("cpuset").asText("").equals(host.path("CpusetCpus").asText(""))&&host.path("CpusetMems").asText("").isEmpty(),"LIVE_RESOURCE_POLICY_DIFFERS");
        require(service.path("blkio_config").path("weight").asLong()==host.path("BlkioWeight").asLong(),"LIVE_RESOURCE_POLICY_DIFFERS");
        require(service.path("oom_kill_disable").asBoolean()==host.path("OomKillDisable").asBoolean()&&service.path("oom_score_adj").asLong()==host.path("OomScoreAdj").asLong(),"LIVE_RESOURCE_POLICY_DIFFERS");
        require(service.path("mem_swappiness").equals(host.path("MemorySwappiness"))||!service.has("mem_swappiness")&&host.path("MemorySwappiness").isNull(),"LIVE_RESOURCE_POLICY_DIFFERS");
        for(String field:List.of("BlkioWeightDevice","BlkioDeviceReadBps","BlkioDeviceWriteBps","BlkioDeviceReadIOps","BlkioDeviceWriteIOps"))require(host.path(field).isMissingNode()||host.path(field).isNull()||host.path(field).isEmpty(),"DEVICE_IO_POLICY_UNSUPPORTED");
        for(String field:List.of("weight_device","device_read_bps","device_write_bps","device_read_iops","device_write_iops"))require(!service.path("blkio_config").has(field),"DEVICE_IO_POLICY_UNSUPPORTED");
        String[] restart=service.path("restart").asText("no").split(":",-1);
        require(restart[0].equals(host.path("RestartPolicy").path("Name").asText())&&(restart.length==2?Integer.parseInt(restart[1]):0)==host.path("RestartPolicy").path("MaximumRetryCount").asInt(),"LIVE_RESOURCE_POLICY_DIFFERS");
    }
    void apply(String plan,boolean rollback)throws Exception {
        require(plan.equals(state.path("plan").asText()),"STALE_PREVIEW");String phase=state.path("phase").asText();
        require(rollback?Set.of("INSTALLED","INSTALLING","INSTALL_FAILED","ROLLING_BACK","ROLLBACK_FAILED").contains(phase):phase.equals("PREPARED"),"ACTION_NOT_AVAILABLE");
        UpdateManifest m=saved(!rollback);stable();JsonNode observed=observe();
        if(!rollback){require(sameObservation(observed,state.path("before")),"DEPLOYMENT_CHANGED_REVIEW_AGAIN");configurationMatches(observed);}else compatible(observed,m,false);
        for(var c:m.document().path("changes")) {
            String service=c.path("service").asText();
            if(!rollback) {
                Path archive=root.resolve("artifact.tar");Files.deleteIfExists(archive);download(c.path("archive").asText(),archive,c.path("archiveBytes").asLong());
                require(hash(archive).equals(c.path("archiveSha256").asText()),"ARTIFACT_HASH_MISMATCH");
                docker("image","load","--input",archive.toString());Files.delete(archive);
                require(JSON.readTree(docker("image","inspect",c.path("toImage").asText())).get(0).path("Id").equals(c.path("toImage")),"CANDIDATE_IMAGE_MISSING");
                sameImageDefaults(c.path("fromImage").asText(),c.path("toImage").asText());
                preserved(service,c.path("fromImage").asText());preserved(service,c.path("toImage").asText());
            } else docker("image","inspect",c.path("fromImage").asText());
        }
        // Refuse drift after potentially slow downloads and immediately before service mutation.
        stable();JsonNode current=observe();if(!rollback)require(sameObservation(current,state.path("before")),"DEPLOYMENT_CHANGED_REVIEW_AGAIN");else compatible(current,m,false);
        if(!rollback){configurationMatches(current);saved(true).fresh();}else saved(false);
        ObjectNode override=state.path("previousOverride").deepCopy();ObjectNode services=(ObjectNode)override.path("services");
        for(var c:m.document().path("changes"))services.putObject(c.path("service").asText()).put("image",c.path(rollback?"fromImage":"toImage").asText()).put("pull_policy","never");
        var restore=state.path("previousOverride").deepCopy();var restoreServices=(ObjectNode)restore.path("services");for(var c:m.document().path("changes"))restoreServices.putObject(c.path("service").asText()).put("image",c.path("fromImage").asText()).put("pull_policy","never");
        write(root.resolve("rollback.compose.json"),restore,false);
        state.remove("error");state.put("phase",rollback?"ROLLING_BACK":"INSTALLING");save();publish(null);write(root.resolve("active.compose.json"),override,false);
        var args=new ArrayList<>(compose(root.resolve("active.compose.json"),"up","--detach","--no-deps","--no-build","--pull","never","--wait","--wait-timeout",config.path("waitSeconds").asText()));
        m.document().path("changes").forEach(c->args.add(c.path("service").asText()));
        try {
            commands.run(args,config.path("waitSeconds").asInt()+60);JsonNode after=observe();compatible(after,m,true);
            for(var c:m.document().path("changes"))require(after.path(c.path("service").asText()).path("image").equals(c.path(rollback?"fromImage":"toImage")),"EXPECTED_IMAGE_NOT_OBSERVED");
            state.put("phase",rollback?"ROLLED_BACK":"INSTALLED");state.set("after",after);save();publish(null);
        } catch(Exception e) {state.put("phase","DOCKER_COMMAND_TIMED_OUT".equals(e.getMessage())?"UNCERTAIN":rollback?"ROLLBACK_FAILED":"INSTALL_FAILED");save();publish("SERVICE_REPLACEMENT_FAILED");throw e;}
    }
    void sameImageDefaults(String previous,String candidate)throws Exception {
        JsonNode old=JSON.readTree(docker("image","inspect",previous)).get(0).path("Config");
        JsonNode next=JSON.readTree(docker("image","inspect",candidate)).get(0).path("Config");
        require(old.isObject()&&next.isObject(),"IMAGE_DEFAULTS_UNAVAILABLE");
        ObjectNode a=old.deepCopy(),b=next.deepCopy();a.remove("Labels");b.remove("Labels");
        require(a.equals(b),"CANDIDATE_RUNTIME_DEFAULTS_CHANGED");
    }
    void reconcileRollback()throws Exception {
        require(Set.of("UNCERTAIN","INSTALL_FAILED","ROLLBACK_FAILED","INSTALLING","ROLLING_BACK").contains(state.path("phase").asText()),"RECONCILIATION_NOT_AVAILABLE");
        var m=saved(false);stable();var current=observe();compatible(current,m,true);
        for(var c:m.document().path("changes"))require(current.path(c.path("service").asText()).path("image").equals(c.path("fromImage")),"PREVIOUS_IMAGE_NOT_OBSERVED");
        write(root.resolve("active.compose.json"),read(root.resolve("rollback.compose.json"),65536),false);configurationMatches(current);state.put("phase","ROLLED_BACK");state.remove("error");save();publish(null);
    }
    void compatible(JsonNode current,UpdateManifest m,boolean running) {
        state.set("lastObservation",current.deepCopy());
        var changed=new HashMap<String,JsonNode>();m.document().path("changes").forEach(c->changed.put(c.path("service").asText(),c));
        for(var e:state.path("before").properties()) {
            JsonNode n=current.path(e.getKey()),old=e.getValue(),c=changed.get(e.getKey());
            require(n.path("mounts").equals(old.path("mounts"))&&comparisonPolicy(n.path("policy")).equals(comparisonPolicy(old.path("policy"))),"RUNTIME_STATE_OR_POLICY_CHANGED");
            require(c==null?n.path("id").equals(old.path("id")):(n.path("image").equals(c.path("fromImage"))||n.path("image").equals(c.path("toImage"))),"UNEXPECTED_DEPLOYMENT");
            if(running)require(n.path("running").asBoolean()&&(!n.has("health")||n.path("health").asText().equals("healthy")),"SERVICE_NOT_READY");
        }
    }
    void preserved(String service,String image)throws Exception {
        String id=docker("create","--network","none","--read-only","--label","app.zcat.stargate.purpose=upgrade-validation","--entrypoint","/stargate-never-started",image).trim();require(id.matches("[a-f0-9]{64}"),"INVALID_VALIDATION_CONTAINER");
        try {
            for(var e:config.path("preserve").path(service).properties()) {
                require(e.getKey().matches("/[A-Za-z0-9_./+-]+")&&!e.getKey().contains("..")&&e.getValue().asText().matches(HASH),"INVALID_PRESERVED_FILE");
                Path out=root.resolve("preserved-file");Files.deleteIfExists(out);docker("cp",id+":"+e.getKey(),out.toString());require(hash(out).equals(e.getValue().asText()),"PRESERVED_RUNTIME_BYTES_CHANGED");Files.delete(out);
            }
        } finally {docker("rm","--volumes",id);}
    }
    void save()throws Exception {write(root.resolve("state.json"),state,false);}
    void publish(String error)throws Exception {
        var p=JSON.createObjectNode().put("schema",1).put("observedAt",Instant.now().toString()).put("phase",state.path("phase").asText()).put("plan",state.path("plan").asText()).put("signer",config.path("publicKeySha256").asText());
        if(state.has("plan")) {
            ObjectNode release=saved(false).document().deepCopy();release.path("changes").forEach(c->((ObjectNode)c).remove("archive"));p.set("release",release);
        }
        if(error!=null)p.put("error",error);write(publicDir.resolve("status.json"),p,true);
    }
    void consume()throws Exception {
        Path request=inbox.resolve("request.json");if(!Files.exists(request,NOFOLLOW_LINKS))return;
        Path claimed=root.resolve("claimed-request.json");require(!Files.exists(claimed,NOFOLLOW_LINKS),"INTERRUPTED_REQUEST_REQUIRES_REVIEW");Files.move(request,claimed,StandardCopyOption.ATOMIC_MOVE);sync(root);sync(inbox);
        try {JsonNode r=JSON.readTree(read(claimed,256));keys(r,"action","plan");String action=text(r,"action","refresh|install|rollback");if(action.equals("refresh"))refresh();else apply(text(r,"plan",HASH),action.equals("rollback"));}
        catch(Exception e){state.put("error","REQUEST_FAILED_CHECK_OPERATOR_LOG");save();publish("REQUEST_FAILED_CHECK_OPERATOR_LOG");System.err.println("Upgrade request failed: "+(e.getMessage()!=null&&e.getMessage().matches("[A-Z_]+")?e.getMessage():"OPERATION_FAILED"));}
        finally {Files.deleteIfExists(claimed);}
    }
    byte[] fetchSmall(String url,int limit)throws Exception {Path p=root.resolve("fetch.tmp");Files.deleteIfExists(p);try{download(url,p,limit,false);return read(p,limit);}finally{Files.deleteIfExists(p);}}
    void download(String url,Path out,long length)throws Exception {download(url,out,length,true);}
    HttpClient downloadClient() {return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).followRedirects(HttpClient.Redirect.NEVER).build();}
    void download(String url,Path out,long limit,boolean exact)throws Exception {
        URI uri=URI.create(url);
        if("file".equals(uri.getScheme())) {
            require(config.path("localArtifactDirectory").isTextual(),"LOCAL_ARTIFACTS_DISABLED");Path dir=Path.of(config.path("localArtifactDirectory").asText()).toRealPath(),file=Path.of(uri);
            require(file.toRealPath().startsWith(dir)&&Files.isRegularFile(file,NOFOLLOW_LINKS),"LOCAL_ARTIFACT_OUTSIDE_ROOT");
            UpdateDownload.local(Files.newInputStream(file,NOFOLLOW_LINKS),out,limit,exact);
        } else {
            UpdateDownload.https(uri);
            try(var client=downloadClient()) {
                UpdateDownload.https(uri,out,limit,exact,client,UpdateDownload.TIMEOUT);
            }
        }
    }
}
