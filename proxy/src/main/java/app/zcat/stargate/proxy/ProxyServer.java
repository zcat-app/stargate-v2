// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.FixedRecvByteBufAllocator;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DecoderResultProvider;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpDecoderConfig;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.proxy.Socks5ProxyHandler;
import io.netty.handler.ssl.SslCloseCompletionEvent;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.resolver.NoopAddressResolverGroup;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.GlobalEventExecutor;
import io.netty.util.concurrent.ScheduledFuture;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** One HTTP exchange per connection; CONNECT and negotiated upgrades become raw tunnels. */
public final class ProxyServer implements AutoCloseable {
    private static final int MAX_PENDING_BYTES = 65536;
    private static final WriteBufferWaterMark WATERMARK = new WriteBufferWaterMark(32768, 65536);
    private final ProxyConfig config;
    private final AggregateMetrics metrics;
    private final I2pLifecycle i2pLifecycle;
    private final NioEventLoopGroup acceptors = new NioEventLoopGroup(1);
    private final NioEventLoopGroup workers = new NioEventLoopGroup(Math.min(4, Runtime.getRuntime().availableProcessors()));
    private final ChannelGroup connections = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    private final Admission admission;
    private final AtomicBoolean closed = new AtomicBoolean();
    private Channel listener;
    private record Credentials(java.util.Map<String, ProxyConfig.Profile> byId, java.util.Map<String, ProxyConfig.Profile> byPartition) {
        static Credentials of(java.util.Map<String, ProxyConfig.Profile> profiles) {
            var partitions = new java.util.HashMap<String, ProxyConfig.Profile>();
            profiles.values().forEach(profile -> partitions.put(profile.partition(), profile));
            return new Credentials(profiles, java.util.Map.copyOf(partitions));
        }
    }
    private volatile Credentials credentials;
    private RemoteTls remoteTls;
    private Channel tlsListener;
    private final java.util.concurrent.ScheduledExecutorService credentialRefresh;
    private final java.nio.file.Path credentialSource;
    private volatile long credentialReadStarted;


    public ProxyServer(ProxyConfig config) { this(config, null); }

    public ProxyServer(ProxyConfig config, java.nio.file.Path source) {
        this.config = config;this.admission = new Admission(config.maxConnections());this.metrics = new AggregateMetrics(config.metricsPath(), admission);this.credentials = Credentials.of(config.profiles());
        try { i2pLifecycle = config.i2pLifecycleDirectory()==null ? null : new I2pLifecycle(config.i2pLifecycleDirectory(),config.i2p(),config.i2pCooldownSeconds()); }
        catch(java.io.IOException e) { throw new IllegalStateException("I2P_LIFECYCLE_UNAVAILABLE",e); }
        credentialSource = source;
        credentialRefresh = source == null ? null : java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
                task -> Thread.ofPlatform().daemon().name("credential-refresh").unstarted(task));
        if (credentialRefresh != null) credentialRefresh.scheduleWithFixedDelay(this::refreshCredentials, 0, 250, TimeUnit.MILLISECONDS);
    }

    private void refreshCredentials() {
        long read = ++credentialReadStarted;
        try { credentials = Credentials.of(ProxyConfig.loadProfiles(credentialSource)); }
        catch (Throwable failure) { credentials = new Credentials(java.util.Map.of(), java.util.Map.of()); }
        // A failed refresh never preserves a previously authorized credential snapshot.
        // This is best effort under VM/resource failure, not a containment guarantee.
        for (Channel channel : connections) {
            Front front = channel.pipeline().get(Front.class);
            if (front != null) try { channel.eventLoop().execute(() -> front.credentialsRefreshed(read)); }
            catch (java.util.concurrent.RejectedExecutionException ignored) { channel.close(); }
        }
    }

    private static boolean credentialSyntax(String authorization) {
        if (authorization == null || authorization.length() > 1024
                || !authorization.regionMatches(true, 0, "Basic ", 0, 6)) return false;
        try {
            String pair = new String(java.util.Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.US_ASCII);
            return pair.matches("[A-Za-z0-9_-]{1,64}:[A-Za-z0-9_-]{32,128}");
        } catch (IllegalArgumentException failure) { return false; }
    }

    private boolean current(ProxyConfig.Profile profile, boolean i2p) {
        var now = credentials.byPartition().get(profile.partition());
        return profile.sameCredential(now) && (!i2p || profile.i2pPort() == now.i2pPort());
    }

    public ProxyServer start() throws InterruptedException {
        try {
            if (config.tls() != null) remoteTls = new RemoteTls(config.tls());
            var bootstrap = new ServerBootstrap().group(acceptors, workers).channelFactory(() -> {
                        try {
                            var family = config.listen().getAddress() instanceof java.net.Inet4Address
                                    ? java.net.StandardProtocolFamily.INET : java.net.StandardProtocolFamily.INET6;
                            return new NioServerSocketChannel(java.nio.channels.ServerSocketChannel.open(family));
                        } catch (java.io.IOException e) { throw new java.io.UncheckedIOException(e); }
                    })
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childOption(ChannelOption.RCVBUF_ALLOCATOR, new FixedRecvByteBufAllocator(8192))
                    .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, WATERMARK)
                    .childHandler(initializer(false));
            listener = bootstrap.bind(config.listen()).sync().channel();
            if (remoteTls != null) tlsListener = bootstrap.clone().childHandler(initializer(true))
                    .bind(new java.net.InetSocketAddress(config.listen().getAddress(), config.tls().port())).sync().channel();
            return this;
        } catch (RuntimeException | InterruptedException e) { close(); throw e; }
    }

    private ChannelInitializer<SocketChannel> initializer(boolean tls) {
        return new ChannelInitializer<SocketChannel>() {
            @Override protected void initChannel(SocketChannel channel) { initializeConnection(channel, tls); }
        };
    }

    void initializeConnection(Channel channel, boolean tls) {
        connections.add(channel);
        boolean overloaded = admission.accept();
        channel.closeFuture().addListener(_ -> admission.release());
        if (tls) {
            if (overloaded) { channel.close(); return; }
            var ssl = remoteTls.context().newHandler(channel.alloc());
            ssl.setHandshakeTimeoutMillis(config.headerTimeoutMillis());
            channel.pipeline().addLast("tls", ssl);
        }
        channel.pipeline().addLast("http", new HttpServerCodec(decoderConfig()));
        channel.pipeline().addLast("headerTimeout", new InitialHeaderDeadline(tls, config.headerTimeoutMillis()));
        channel.pipeline().addLast("front", new Front(overloaded));
    }

    public int port() { return ((InetSocketAddress) listener.localAddress()).getPort(); }
    public void await() throws InterruptedException { listener.closeFuture().sync(); }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        if (credentialRefresh != null) credentialRefresh.shutdownNow();
        if (listener != null) listener.close().awaitUninterruptibly();
        if (tlsListener != null) tlsListener.close().awaitUninterruptibly();
        if (remoteTls != null) remoteTls.close();
        connections.close().awaitUninterruptibly();
        acceptors.shutdownGracefully(0, 3, TimeUnit.SECONDS).awaitUninterruptibly();
        workers.shutdownGracefully(0, 3, TimeUnit.SECONDS).awaitUninterruptibly();
        if(i2pLifecycle!=null)i2pLifecycle.close();
        metrics.close();
    }

    private static HttpDecoderConfig decoderConfig() {
        return new HttpDecoderConfig().setMaxInitialLineLength(8192).setMaxHeaderSize(16384)
                .setMaxChunkSize(8192).setAllowDuplicateContentLengths(false).setStrictLineParsing(true);
    }

    /** Bounds the first request head, independent of how frequently bytes arrive. */
    private static final class InitialHeaderDeadline extends ChannelInboundHandlerAdapter {
        private final boolean tls;
        private final long timeoutNanos;
        private ScheduledFuture<?> deadline;
        private long started;
        private boolean startedDeadline;

        InitialHeaderDeadline(boolean tls, int timeoutMillis) {
            this.tls = tls;
            timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        }

        private void start(ChannelHandlerContext ctx) {
            if (startedDeadline) return;
            startedDeadline = true;
            started = System.nanoTime();
            deadline = ctx.executor().schedule(() -> { ctx.close(); }, timeoutNanos, TimeUnit.NANOSECONDS);
        }

        @Override public void channelActive(ChannelHandlerContext ctx) {
            if (!tls) start(ctx);
            ctx.fireChannelActive();
        }

        @Override public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
            if (tls && event instanceof SslHandshakeCompletionEvent handshake && handshake.isSuccess()) start(ctx);
            ctx.fireUserEventTriggered(event);
        }

        @Override public void channelRead(ChannelHandlerContext ctx, Object message) {
            if (message instanceof HttpRequest) {
                // A busy event loop might process a decoded head before its overdue timer.
                if (startedDeadline && System.nanoTime() - started >= timeoutNanos) {
                    ReferenceCountUtil.release(message);
                    ctx.close();
                    return;
                }
                ctx.pipeline().remove(this);
            }
            ctx.fireChannelRead(message);
        }

        @Override public void handlerRemoved(ChannelHandlerContext ctx) {
            if (deadline != null) deadline.cancel(false);
        }

        @Override public void channelInactive(ChannelHandlerContext ctx) {
            if (deadline != null) deadline.cancel(false);
            ctx.fireChannelInactive();
        }
    }

    private enum State { INITIAL, AUTHENTICATING, CONNECTING, HTTP, TUNNEL, CLOSED }

    private final class Front extends ChannelInboundHandlerAdapter {
        private final boolean overloaded;
        private ChannelHandlerContext context;
        private Channel upstream;
        private State state = State.INITIAL;
        private final ArrayDeque<Object> pending = new ArrayDeque<>();
        private int pendingBytes;
        private ScheduledFuture<?> setupTimeout;
        private boolean requestEnded;
        private boolean responseStarted;
        private boolean counted;
        private boolean upstreamFailed;
        private String requestedUpgrade;
        private HttpRequest outgoing;
        private RequestTarget target;
        private String network;
        private boolean destinationObserved;
        private ProxyConfig.Profile credential;
        private HttpRequest authenticationRequest;
        private long authenticationRead;
        private I2pLifecycle.Lease i2pLease;
        private boolean frontClosed, retryScheduled;
        private int openUpstreams, connectCalls, attempt;
        private void releaseLeaseIfClosed() {
            if(i2pLease!=null && frontClosed && openUpstreams==0 && connectCalls==0) {
                i2pLease.close();i2pLease=null;
            }
        }
        private void checkCredential() {
            if (credential != null && !current(credential, target != null && target.i2p())) closePair();
        }

        private void credentialsRefreshed(long read) {
            checkCredential();
            if (state != State.AUTHENTICATING || read <= authenticationRead || !context.channel().isActive()) return;
            HttpRequest retry = authenticationRequest;
            authenticationRequest = null;
            cancelTimeout();
            state = State.INITIAL;
            begin(retry, true);
        }

        Front(boolean overloaded) { this.overloaded = overloaded; }

        @Override public void channelActive(ChannelHandlerContext ctx) {
            context = ctx;
            if (overloaded) fail(HttpResponseStatus.SERVICE_UNAVAILABLE, "CONNECTION_LIMIT");
            else ctx.fireChannelActive();
        }

        @Override public void channelRead(ChannelHandlerContext ctx, Object message) {
            checkCredential();
            if (state == State.CLOSED) { ReferenceCountUtil.release(message); return; }
            if (state == State.TUNNEL && message instanceof ByteBuf) { sendUpstream(message); return; }
            if (message instanceof DecoderResultProvider result && result.decoderResult().isFailure()) {
                ReferenceCountUtil.release(message); fail(HttpResponseStatus.BAD_REQUEST, "INVALID_HTTP"); return;
            }
            if (message instanceof HttpRequest request) {
                if (state != State.INITIAL) {
                    ReferenceCountUtil.release(message); closePair(); return;
                }
                begin(request, false);
                ReferenceCountUtil.release(message);
            } else if (message instanceof HttpContent content) {
                if (target == null || requestEnded) {
                    ReferenceCountUtil.release(message); closePair(); return;
                }
                if (content instanceof LastHttpContent last) {
                    requestEnded = true;
                    stripHopHeaders(last.trailingHeaders());
                }
                if (target.tunnel()) {
                    boolean empty = content.content().readableBytes() == 0;
                    ReferenceCountUtil.release(message);
                    if (!empty) fail(HttpResponseStatus.BAD_REQUEST, "CONNECT_BODY_UNSUPPORTED");
                } else if (state == State.AUTHENTICATING || state == State.CONNECTING) {
                    pendingBytes += content.content().readableBytes();
                    if (pendingBytes > MAX_PENDING_BYTES || pending.size() >= 32) {
                        ReferenceCountUtil.release(message); fail(HttpResponseStatus.valueOf(413), "SETUP_BUFFER_LIMIT");
                    } else pending.add(message);
                } else if (state == State.HTTP) sendUpstream(message);
                else ReferenceCountUtil.release(message);
            } else {
                ReferenceCountUtil.release(message); closePair();
            }
        }

        private void begin(HttpRequest request, boolean refreshed) {
            try { target = RequestTarget.parse(request); }
            catch (IllegalArgumentException e) { fail(HttpResponseStatus.BAD_REQUEST, "INVALID_TARGET"); return; }
            // Refuse unsupported routes without prompting for credentials we cannot use.
            if (!target.onion() && !target.i2p() && !(config.nym() != null && target.publicWeb())) { fail(HttpResponseStatus.FORBIDDEN, "PRIVATE_NETWORK_ROUTES_ONLY"); return; }
            network = target.onion() ? "TOR" : target.i2p() ? "I2P" : "NYM";
            if (request.headers().getAll(HttpHeaderNames.PROXY_AUTHORIZATION).size() != 1
                    || !credentialSyntax(request.headers().get(HttpHeaderNames.PROXY_AUTHORIZATION))) {
                fail(HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED, "AUTH_REQUIRED"); return;
            }
            ProxyConfig.Profile profile = ProxyConfig.authenticate(request.headers().get(HttpHeaderNames.PROXY_AUTHORIZATION), credentials.byId());
            if (profile == null && credentialRefresh != null && !refreshed) {
                state = State.AUTHENTICATING;
                authenticationRead = credentialReadStarted;
                context.channel().config().setAutoRead(false);
                // Only a read begun after this miss can observe newly published credentials.
                // Copy the head; already-decoded body chunks use the bounded pending queue.
                authenticationRequest = new DefaultHttpRequest(request.protocolVersion(), request.method(), request.uri());
                authenticationRequest.headers().set(request.headers());
                setupTimeout = context.executor().schedule(() -> fail(HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED, "AUTH_REQUIRED"), config.headerTimeoutMillis(), TimeUnit.MILLISECONDS);
                return;
            }
            if (profile == null) { fail(HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED, "AUTH_REQUIRED"); return; }
            credential = profile;
            if (target.i2p() && config.i2p() == null) { fail(HttpResponseStatus.BAD_GATEWAY, "I2P_NOT_CONFIGURED"); return; }
            if (target.i2p() && profile.i2pPort() == 0) { fail(HttpResponseStatus.BAD_GATEWAY, "I2P_DEVICE_UNAVAILABLE"); return; }
            for (String connection : request.headers().getAll(HttpHeaderNames.CONNECTION)) {
                for (String option : connection.split(",")) {
                    if (List.of("host", "content-length", "transfer-encoding", "proxy-authorization")
                            .contains(option.trim().toLowerCase(java.util.Locale.ROOT))) {
                        fail(HttpResponseStatus.BAD_REQUEST, "INVALID_CONNECTION_OPTIONS"); return;
                    }
                }
            }
            String transfer = request.headers().get(HttpHeaderNames.TRANSFER_ENCODING);
            if (transfer != null && !transfer.equalsIgnoreCase("chunked")) {
                fail(HttpResponseStatus.BAD_REQUEST, "UNSUPPORTED_TRANSFER_CODING"); return;
            }
            if (target.tunnel() && (HttpUtil.getContentLength(request, 0) != 0 || HttpUtil.isTransferEncodingChunked(request))) {
                fail(HttpResponseStatus.BAD_REQUEST, "CONNECT_BODY_UNSUPPORTED"); return;
            }
            counted = true;metrics.connections.incrementAndGet();metrics.active.incrementAndGet();
            if (target.i2p()) metrics.i2pConnections.incrementAndGet();
            if (network.equals("NYM")) metrics.nymConnections.incrementAndGet();
            requestedUpgrade = request.headers().get(HttpHeaderNames.UPGRADE);
            if (!target.tunnel()) {
                boolean chunked = HttpUtil.isTransferEncodingChunked(request);
                outgoing = new DefaultHttpRequest(HttpVersion.HTTP_1_1, request.method(), target.originForm());
                outgoing.headers().set(request.headers());
                stripHopHeaders(outgoing.headers());
                outgoing.headers().set(HttpHeaderNames.HOST, target.authority());
                if (chunked) HttpUtil.setTransferEncodingChunked(outgoing, true);
                if (requestedUpgrade != null) {
                    outgoing.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.UPGRADE);
                    outgoing.headers().set(HttpHeaderNames.UPGRADE, requestedUpgrade);
                } else outgoing.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
            }
            state = State.CONNECTING;
            context.channel().config().setAutoRead(false);
            int timeout = network.equals("NYM") ? config.nymSetupTimeoutMillis() : target.i2p() ? config.i2pSetupTimeoutMillis() : config.setupTimeoutMillis();
            setupTimeout = context.executor().schedule(() -> fail(HttpResponseStatus.GATEWAY_TIMEOUT, network + "_SETUP_TIMEOUT"), timeout, TimeUnit.MILLISECONDS);
            if(target.i2p() && i2pLifecycle!=null && profile.i2pPort()>0) {
                String id=credentials.byId().entrySet().stream().filter(e->e.getValue().partition().equals(profile.partition())).map(java.util.Map.Entry::getKey).findFirst().orElse(null);
                if(id==null){fail(HttpResponseStatus.BAD_GATEWAY,"I2P_DEVICE_UNAVAILABLE");return;}
                String key=java.util.HexFormat.of().formatHex(ProxyConfig.digest(id.getBytes(StandardCharsets.US_ASCII)));
                i2pLifecycle.acquireAsync(profile.i2pPort(),key).whenComplete((lease,acquireError)-> {
                    try { context.executor().execute(()-> {
                        if(lease!=null)i2pLease=lease;
                        checkCredential();
                        if(state!=State.CONNECTING||!context.channel().isActive()){releaseLeaseIfClosed();return;}
                        if(acquireError!=null){fail(HttpResponseStatus.SERVICE_UNAVAILABLE,"I2P_LIFECYCLE_UNAVAILABLE");return;}
                        lease.ready().whenComplete((unused,error)-> {
                            try {context.executor().execute(()-> {
                                checkCredential();
                                if(state!=State.CONNECTING||!context.channel().isActive()){releaseLeaseIfClosed();return;}
                                if(error!=null){fail(HttpResponseStatus.SERVICE_UNAVAILABLE,"I2P_ACTIVATION_UNAVAILABLE");return;}
                                connectUpstream();
                            });}catch(java.util.concurrent.RejectedExecutionException ignored){lease.close();}
                        });
                    }); }catch(java.util.concurrent.RejectedExecutionException ignored){if(lease!=null)lease.close();}
                });
            } else connectUpstream();
        }

        private void connectUpstream() {
            checkCredential();
            if(state!=State.CONNECTING || !context.channel().isActive())return;
            retryScheduled=false;
            int thisAttempt=++attempt;
            int timeout = network.equals("NYM") ? config.nymSetupTimeoutMillis() : target.i2p() ? config.i2pSetupTimeoutMillis() : config.setupTimeoutMillis();
            InetSocketAddress configured = network.equals("NYM") ? config.nym() : target.i2p() ? config.i2p() : config.tor();
            if (target.i2p() && credential.i2pPort() > 0)
                configured = InetSocketAddress.createUnresolved(configured.getHostString(), credential.i2pPort());
            InetSocketAddress endpoint = config.containerNetwork()
                    || configured.isUnresolved() ? new InetSocketAddress(configured.getHostString(), configured.getPort()) : configured;
            if (endpoint.isUnresolved() || !(endpoint.getAddress().isLoopbackAddress()
                    || (config.containerNetwork() && endpoint.getAddress().isSiteLocalAddress()))) {
                fail(HttpResponseStatus.BAD_GATEWAY, network + "_UNAVAILABLE");return;
            }
            // i2pd ignores credentials; Nym uses NoAuth. Only Tor receives an isolation partition.
            Socks5ProxyHandler socks = !target.onion() ? new Socks5ProxyHandler(endpoint)
                    : new Socks5ProxyHandler(endpoint, credential.partition(), "");
            socks.setConnectTimeoutMillis(0);
            Bootstrap bootstrap = new Bootstrap().group(context.channel().eventLoop()).channel(NioSocketChannel.class)
                    .resolver(NoopAddressResolverGroup.INSTANCE)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeout)
                    .option(ChannelOption.WRITE_BUFFER_WATER_MARK, WATERMARK)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override protected void initChannel(SocketChannel channel) {
                            upstream = channel;openUpstreams++;
                            channel.closeFuture().addListener(_->{openUpstreams--;releaseLeaseIfClosed();});
                            connections.add(channel);
                            channel.pipeline().addLast("socks", socks);
                            if (!target.tunnel()) channel.pipeline().addLast("http", new HttpClientCodec());
                            channel.pipeline().addLast("back", new Back(Front.this,thisAttempt));
                        }
                    });
            // The unresolved address and disabled Bootstrap resolver prevent local DNS lookup.
            connectCalls++;
            try {
                bootstrap.connect(InetSocketAddress.createUnresolved(target.host(), target.port()))
                        .addListener(future -> { connectCalls--;if(!future.isSuccess())setupFailed(thisAttempt);releaseLeaseIfClosed(); });
            }catch(RuntimeException e){connectCalls--;setupFailed(thisAttempt);releaseLeaseIfClosed();return;}
            socks.connectFuture().addListener(future -> {
                if(thisAttempt!=attempt)return;
                if (!future.isSuccess()) { setupFailed(thisAttempt); return; }
                checkCredential();
                if (state != State.CONNECTING || !context.channel().isActive()) { upstream.close(); return; }
                // Nym ACKs locally before sending to the mixnet: retain the deadline until destination data.
                if (!network.equals("NYM")) cancelTimeout();
                if(i2pLease!=null)i2pLease.connected();
                metrics.connected.incrementAndGet();
                if (target.i2p()) metrics.i2pConnected.incrementAndGet();
                if (network.equals("NYM")) metrics.nymConnected.incrementAndGet();
                if (target.tunnel()) {
                    context.writeAndFlush(new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK))
                            .addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
                    state = State.TUNNEL;
                    remove(context.channel(), "http");
                } else {
                    state = State.HTTP;
                    upstream.write(outgoing).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
                    outgoing = null;
                    while (!pending.isEmpty()) {
                        Object queued = pending.remove();metrics.uploaded.addAndGet(contentBytes(queued));
                        upstream.write(queued).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
                    }
                    pendingBytes = 0;
                    upstream.flush();
                }
                context.channel().config().setAutoRead(upstream.isWritable());
            });
        }

        private void setupFailed(int failedAttempt) {
            if(state!=State.CONNECTING || failedAttempt!=attempt || retryScheduled)return;
            if(i2pLease==null){fail(HttpResponseStatus.BAD_GATEWAY,network+"_UNAVAILABLE");return;}
            // No destination HTTP bytes have been sent. Keep the one setup deadline and lease.
            retryScheduled=true;
            if(upstream!=null)upstream.close().addListener(_->context.executor().schedule(this::connectUpstream,1000,TimeUnit.MILLISECONDS));
            else context.executor().schedule(this::connectUpstream,1000,TimeUnit.MILLISECONDS);
        }

        private void sendUpstream(Object message) {
            if (upstream == null || !upstream.isActive()) { ReferenceCountUtil.release(message); closePair(); return; }
            metrics.uploaded.addAndGet(contentBytes(message));
            upstream.writeAndFlush(message).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
            if (!upstream.isWritable()) context.channel().config().setAutoRead(false);
        }

        private void observeDestination() {
            if (!destinationObserved) {
                destinationObserved = true;
                cancelTimeout();
                if (network.equals("NYM")) metrics.nymResponses.incrementAndGet();
                if (target.i2p()) metrics.i2pResponses.incrementAndGet();
            }
        }

        @Override public void channelWritabilityChanged(ChannelHandlerContext ctx) {
            if (upstream != null) upstream.config().setAutoRead(ctx.channel().isWritable());
            ctx.fireChannelWritabilityChanged();
        }
        @Override public void channelReadComplete(ChannelHandlerContext ctx) {
            // Read bounded setup data and EOF even while normal reads are paused.
            if (state == State.CONNECTING && pendingBytes <= MAX_PENDING_BYTES - 8192 && pending.size() < 31) ctx.read();
            ctx.fireChannelReadComplete();
        }
        @Override public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
            // A peer's close_notify ends TLS without necessarily closing its TCP socket.
            if (event instanceof SslCloseCompletionEvent) closePair();
            ctx.fireUserEventTriggered(event);
        }
        @Override public void channelInactive(ChannelHandlerContext ctx) {
            frontClosed=true;
            if (counted) { counted = false;metrics.active.decrementAndGet(); }
            closePair();releaseLeaseIfClosed();
        }
        @Override public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if (state == State.INITIAL) fail(HttpResponseStatus.REQUEST_TIMEOUT, "HEADER_OR_HTTP_FAILURE");
            else closePair();
        }

        private void cancelTimeout() { if (setupTimeout != null) { setupTimeout.cancel(false); setupTimeout = null; } }
        private void releasePending() {
            authenticationRequest = null;
            while (!pending.isEmpty()) ReferenceCountUtil.release(pending.remove());
            pendingBytes = 0;
        }
        private void closePair() {
            state = State.CLOSED;
            cancelTimeout(); releasePending();
            if (upstream != null) upstream.close();
            if (context != null) context.close();
        }
        private void finishTunnel() {
            state = State.CLOSED;
            cancelTimeout(); releasePending();
            if (upstream != null) upstream.close();
            context.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
        private void fail(HttpResponseStatus status, String code) {
            if (state == State.CLOSED) return;
            if (counted && !upstreamFailed && (status.code() == 502 || status.code() == 504)) {
                upstreamFailed = true;metrics.failures.incrementAndGet();
            }
            if (state == State.TUNNEL || responseStarted) { closePair(); return; }
            state = State.CLOSED;
            cancelTimeout(); releasePending();
            if (upstream != null) upstream.close();
            byte[] body = (code + "\n").getBytes(StandardCharsets.US_ASCII);
            var response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.wrappedBuffer(body));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
            response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, body.length);
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
            if (status.equals(HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED))
                response.headers().set(HttpHeaderNames.PROXY_AUTHENTICATE, "Basic realm=\"Stargate\", charset=\"UTF-8\"");
            context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
    }

    private final class Back extends ChannelInboundHandlerAdapter {
        private final Front front;
        private boolean informational;
        private boolean upgrading;
        private boolean complete;

        private final int attempt;
        Back(Front front,int attempt) { this.front = front;this.attempt=attempt; }

        @Override public void channelRead(ChannelHandlerContext ctx, Object message) {
            if(attempt!=front.attempt){ReferenceCountUtil.release(message);ctx.close();return;}
            front.checkCredential();
            if (front.state == State.CLOSED || !front.context.channel().isActive()) { ReferenceCountUtil.release(message); ctx.close(); return; }
            if (front.state == State.TUNNEL && message instanceof ByteBuf) {
                if (contentBytes(message) > 0) front.observeDestination();
                metrics.downloaded.addAndGet(contentBytes(message));
                front.context.writeAndFlush(message).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
            } else if (message instanceof HttpResponse response) {
                if (response.decoderResult().isFailure()) { ReferenceCountUtil.release(message); front.fail(HttpResponseStatus.BAD_GATEWAY, front.network + "_INVALID_HTTP"); return; }
                informational = response.status().code() < 200 && response.status().code() != 101;
                if (!informational) front.observeDestination();
                upgrading = response.status().code() == 101;
                if (upgrading && (front.requestedUpgrade == null || !front.requestedUpgrade.equalsIgnoreCase(response.headers().get(HttpHeaderNames.UPGRADE)))) {
                    ReferenceCountUtil.release(message); front.fail(HttpResponseStatus.BAD_GATEWAY, "UNEXPECTED_UPGRADE"); return;
                }
                List<String> transferEncoding = List.copyOf(response.headers().getAll(HttpHeaderNames.TRANSFER_ENCODING));
                stripHopHeaders(response.headers());
                if (!transferEncoding.isEmpty()) {
                    response.headers().set(HttpHeaderNames.TRANSFER_ENCODING, transferEncoding);
                    response.headers().remove(HttpHeaderNames.CONTENT_LENGTH);
                }
                if (upgrading) {
                    response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.UPGRADE);
                    response.headers().set(HttpHeaderNames.UPGRADE, front.requestedUpgrade);
                } else if (!informational) response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
                front.responseStarted |= !informational;
                front.context.writeAndFlush(message).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
                if (upgrading) {
                    front.state = State.TUNNEL;
                    remove(front.context.channel(), "http");
                    remove(ctx.channel(), "http");
                }
            } else if (message instanceof HttpContent content) {
                if (content.decoderResult().isFailure()) { ReferenceCountUtil.release(message); front.closePair(); return; }
                if (content instanceof LastHttpContent last) stripHopHeaders(last.trailingHeaders());
                if (upgrading) { ReferenceCountUtil.release(message); return; }
                metrics.downloaded.addAndGet(content.content().readableBytes());
                if (content instanceof LastHttpContent && !informational) {
                    complete = true;
                    front.context.writeAndFlush(message).addListener(_ -> front.closePair());
                } else front.context.writeAndFlush(message).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
            } else { ReferenceCountUtil.release(message); front.closePair(); }
            if (!front.context.channel().isWritable()) ctx.channel().config().setAutoRead(false);
        }
        @Override public void channelWritabilityChanged(ChannelHandlerContext ctx) {
            if (attempt==front.attempt && (front.state == State.HTTP || front.state == State.TUNNEL))
                front.context.channel().config().setAutoRead(ctx.channel().isWritable());
            ctx.fireChannelWritabilityChanged();
        }
        @Override public void channelInactive(ChannelHandlerContext ctx) {
            if(attempt!=front.attempt)return;
            if(front.state==State.CONNECTING && front.i2pLease!=null){front.setupFailed(attempt);return;}
            if (!complete && front.state != State.CLOSED) {
                if (front.state == State.TUNNEL) front.finishTunnel();
                else front.fail(HttpResponseStatus.BAD_GATEWAY, front.network + "_CLOSED");
            }
        }
        @Override public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if(attempt!=front.attempt)return;
            if(front.state==State.CONNECTING && front.i2pLease!=null)front.setupFailed(attempt);
            else front.fail(HttpResponseStatus.BAD_GATEWAY, front.network + "_FAILURE");
        }
    }

    private static void stripHopHeaders(HttpHeaders headers) {
        if (headers.isEmpty()) return; // Netty's empty last-content trailers are immutable.
        List<String> fields = new ArrayList<>();
        for (String connection : headers.getAll(HttpHeaderNames.CONNECTION))
            for (String name : connection.split(",")) fields.add(name.trim());
        for (String field : fields) headers.remove(field);
        for (String field : List.of("Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Authorization", "Proxy-Authenticate"))
            headers.remove(field);
    }
    private static int contentBytes(Object message) {
        return message instanceof ByteBuf buffer ? buffer.readableBytes()
                : message instanceof HttpContent content ? content.content().readableBytes() : 0;
    }
    private static void remove(Channel channel, String name) {
        if (channel.pipeline().get(name) != null) channel.pipeline().remove(name);
    }
}
