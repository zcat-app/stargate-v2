// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.nio.file.Path;

public final class Main {
    public static void main(String[] args) {
        if (args.length != 2 || !args[0].equals("--config")) {
            System.err.println("Usage: java -jar stargate-proxy.jar --config FILE");
            System.exit(2);
        }
        try {
            ProxyConfig config = ProxyConfig.load(Path.of(args[1]));
            ProxyServer server = new ProxyServer(config, Path.of(args[1])).start();
            Runtime.getRuntime().addShutdownHook(new Thread(server::close, "proxy-shutdown"));
            System.out.println("PROXY_STARTED port=" + server.port() + " pid=" + ProcessHandle.current().pid());
            server.await();
        } catch (Exception e) {
            System.err.println("PROXY_START_FAILED " + e.getClass().getSimpleName());
            System.exit(1);
        }
    }
}
