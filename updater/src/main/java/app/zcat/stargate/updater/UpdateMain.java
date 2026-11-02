// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;
import java.nio.file.*;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static app.zcat.stargate.updater.UpdateFiles.*;

public final class UpdateMain {
    public static void main(String[] args)throws Exception {
        if(args.length!=2||!Set.of("serve","refresh","status","reconcile-rollback").contains(args[0]))throw new IllegalArgumentException("Usage: java -jar updater.jar serve|refresh|status|reconcile-rollback /absolute/private/config.json");
        Path config=Path.of(args[1]);privateFile(config);var settings=json(config);Path socket=localSocket(settings);
        Path root=Path.of(settings.path("workDirectory").asText());directory(root,"rwx------");
        try(var channel=FileChannel.open(root.resolve("lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=channel.tryLock()) {
            require(lock!=null,"UPDATER_ALREADY_RUNNING");
            UpdateEngine.Commands commands=(arguments,seconds)-> {
                var command=new ArrayList<String>(List.of("/usr/bin/docker","--host","unix://"+socket));command.addAll(arguments);
                var builder=new ProcessBuilder(command);
                for(String variable:List.of("DOCKER_HOST","DOCKER_CONTEXT","DOCKER_TLS","DOCKER_TLS_VERIFY","DOCKER_CERT_PATH"))builder.environment().remove(variable);
                return capture(builder,root,seconds);
            };
            var engine=new UpdateEngine(config,commands);
            if(args[0].equals("reconcile-rollback")){engine.reconcileRollback();return;}
            if(args[0].equals("refresh")){engine.refresh();return;}
            if(args[0].equals("status")){engine.publish(null);System.out.println(Files.readString(engine.publicDir.resolve("status.json")));return;}
            // Interrupted transactions are never replayed automatically; their journal permits explicit rollback.
            engine.publish(null);while(true){engine.consume();engine.publish(engine.state.path("error").isTextual()?engine.state.path("error").asText():null);Thread.sleep(2000);}
        }
    }
    static String capture(ProcessBuilder builder,Path root,int seconds)throws Exception {
        // Inspect/config responses can contain operator secrets. Parse privately,
        // then delete on every outcome; never retain them as diagnostic logs.
        Path output=Files.createTempFile(root,".command-",".tmp",java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
        try {
            var p=builder.redirectErrorStream(true).redirectOutput(output.toFile()).start();
            if(!p.waitFor(seconds,TimeUnit.SECONDS)){terminateTree(p);throw new IllegalStateException("DOCKER_COMMAND_TIMED_OUT");}
            require(p.exitValue()==0,"DOCKER_COMMAND_FAILED");return new String(read(output,8*1024*1024),java.nio.charset.StandardCharsets.UTF_8);
        }finally{Files.deleteIfExists(output);}
    }
    static Path localSocket(com.fasterxml.jackson.databind.JsonNode config)throws Exception {
        Path socket=Path.of(config.required("dockerSocket").asText());require(socket.isAbsolute()&&socket.normalize().equals(socket)&&socket.toRealPath().equals(socket),"LOCAL_DOCKER_SOCKET_REQUIRED");
        trustedAncestors(socket.getParent());int mode=((Number)Files.getAttribute(socket,"unix:mode")).intValue();
        require((mode&0170000)==0140000,"LOCAL_DOCKER_SOCKET_REQUIRED");
        require(Files.getOwner(socket).equals(Files.getOwner(Path.of("/proc/self")))||((Number)Files.getAttribute(socket,"unix:uid")).intValue()==0,"UNTRUSTED_DOCKER_SOCKET");return socket;
    }
    static void terminateTree(Process p)throws Exception {
        var children=p.descendants().toList();for(var child:children.reversed())child.destroyForcibly();p.destroyForcibly();
        for(var child:children)try{child.onExit().get(10,TimeUnit.SECONDS);}catch(java.util.concurrent.TimeoutException e){throw new IllegalStateException("DOCKER_COMMAND_TIMED_OUT");}
        require(p.waitFor(10,TimeUnit.SECONDS),"DOCKER_COMMAND_TIMED_OUT");
    }
}
