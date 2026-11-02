// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** One bounded send through the existing Java SimpleX runtime; uncertain sends never retry. */
final class MonitorSender {
    interface Send {String send(byte[] body) throws Exception;}
    static final Map<String,Integer> RESULTS=Map.of("ACCEPTED",0,"REJECTED",2,"NOT_SUBMITTED",3,"UNKNOWN",4,"INVALID_INPUT",64);
    static String dispatch(Path directory,String id,String text,Send sender) throws Exception {
        if(!id.matches("[0-9a-f]{32}-[1-9][0-9]{0,18}")||Long.parseLong(id.substring(33))<=0)throw new IllegalArgumentException("invalid event ID");
        byte[] body=text.getBytes(StandardCharsets.UTF_8);if(body.length<1||body.length>4000)throw new IllegalArgumentException("invalid alert size");
        Path attempt=directory.resolve("event-"+id+".attempt"),result=directory.resolve("event-"+id+".result");
        if(Files.exists(result,LinkOption.NOFOLLOW_LINKS)) {
            if(!Files.exists(attempt,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("receipt has no attempt");
            MonitorFiles.read(attempt,64,true);
            return Arrays.equals(MonitorFiles.read(result,64,true),"ACCEPTED\n".getBytes(StandardCharsets.US_ASCII))?"RECOVERED_ACCEPTED":"BLOCKED";
        }
        if(Files.exists(attempt,LinkOption.NOFOLLOW_LINKS))return "BLOCKED";
        MonitorFiles.create(attempt,"UNKNOWN\n".getBytes(StandardCharsets.US_ASCII));
        String token;
        try {token=sender.send(body);if(!RESULTS.containsKey(token))token="UNKNOWN";}catch(Exception e){token="UNKNOWN";}
        MonitorFiles.create(result,(token+"\n").getBytes(StandardCharsets.US_ASCII));return token;
    }
    static void profile(Path profile) throws Exception {
        MonitorFiles.directory(profile.getParent(),false);
        if(!profile.isAbsolute()||!profile.equals(profile.normalize())||!Files.isDirectory(profile,LinkOption.NOFOLLOW_LINKS)
                ||((Number)MonitorFiles.attribute(profile,"uid")).intValue()!=10001
                ||((Number)MonitorFiles.attribute(profile,"gid")).intValue()!=10001
                ||(((Number)MonitorFiles.attribute(profile,"mode")).intValue()&07777)!=0700)throw new IllegalArgumentException("private sender profile required");
    }
    static String send(Path source,Path profile,String contact,byte[] body) throws Exception {
        profile(profile);
        if(!contact.matches("[1-9][0-9]{0,18}")||Long.parseLong(contact)<=0)throw new IllegalArgumentException("invalid recipient");
        var command=List.of("/usr/bin/docker","--host","unix:///var/run/docker.sock","compose","--ansi","never","--project-name","stargate-simplex-alert","--file",source.resolve("compose.simplex-alert.yaml").toString(),"--env-file","/dev/null","exec","-T","simplex-alert","/opt/java/bin/java","-XX:ErrorFile=/dev/null","-XX:-CreateCoredumpOnCrash","-jar","/opt/simplex/simplex-alert.jar");
        var pb=new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);pb.environment().clear();pb.environment().put("PATH","/usr/bin:/bin");pb.environment().put("SIMPLEX_ALERT_PROFILE",profile.toString());pb.environment().put("SIMPLEX_ALERT_CONTACT_ID",contact);
        Process child=pb.start();
        try(var executor=Executors.newVirtualThreadPerTaskExecutor()) {
            var output=executor.submit(()->child.getInputStream().readNBytes(65));
            var input=executor.submit(()->{try(var stream=child.getOutputStream()){stream.write(body);}return true;});
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(45);
            try {
                input.get(Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);
                byte[] bytes=output.get(Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);
                if(bytes.length>64||!child.waitFor(Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS))return "UNKNOWN";
                for(var entry:RESULTS.entrySet())if(child.exitValue()==entry.getValue()&&Arrays.equals(bytes,(entry.getKey()+"\n").getBytes(StandardCharsets.US_ASCII)))return entry.getKey();
                return "UNKNOWN";
            }catch(Exception e){return "UNKNOWN";}
            finally {child.descendants().forEach(ProcessHandle::destroyForcibly);child.destroyForcibly();child.getInputStream().close();child.getOutputStream().close();input.cancel(true);output.cancel(true);}
        }
    }
}
