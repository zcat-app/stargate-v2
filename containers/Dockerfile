FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 zlib1g \
    && rm -rf /var/lib/apt/lists/*

FROM base AS os-packages
COPY packages/ /packages/
RUN apt-get update && apt-get install -y --no-install-recommends /packages/tor_*.deb /packages/tor-geoipdb_*.deb \
    /packages/i2pd_*.deb \
    /packages/libc6_*_amd64.deb \
    && rm -rf /packages /var/lib/apt/lists/* \
    && mkdir -p /var/lib/tor /run/tor-control && chown -R 10001:10001 /var/lib/tor /run/tor-control

FROM scratch AS app
COPY rootfs-app/ /
COPY --chown=10001:10001 owned-app/ /
COPY java/ /opt/java/
COPY app/ /app/
ENV LANG=C.UTF-8
USER 10001:10001
WORKDIR /app
EXPOSE 8881 9080
ENTRYPOINT ["/opt/java/bin/java", "-cp", "/app/proxy.jar", "app.zcat.stargate.runtime.Supervisor", "/app", "/data", "/run/stargate"]

FROM scratch AS tor
COPY rootfs-tor/ /
COPY --chown=10001:10001 owned-tor/ /
COPY torrc /etc/tor/stargate-torrc
ENV LANG=C.UTF-8
USER 10001:10001
ENTRYPOINT ["/usr/bin/tor", "-f", "/etc/tor/stargate-torrc"]

FROM scratch AS i2p
COPY rootfs-i2p/ /
COPY --chown=10001:10001 owned-i2p/ /
ENV LANG=C.UTF-8
USER 10001:10001
ENTRYPOINT ["/usr/bin/stargate-i2p-owner", "/run/i2p-control/tunnels.conf", "/usr/bin/i2pd", "--datadir=/var/lib/i2pd", "--conf=/run/i2p-control/i2pd.conf", "--certsdir=/usr/share/i2pd/certificates", "--tunconf=/run/i2p-control/tunnels.conf", "--tunnelsdir=/etc/i2pd/tunnels.d"]

FROM scratch AS nym
COPY rootfs-app/ /
COPY --chown=10001:10001 owned-nym/ /
COPY java/ /opt/java/
COPY app/proxy.jar /app/proxy.jar
COPY nym/ /opt/nym/
ENV LANG=C.UTF-8
USER 10001:10001
ENTRYPOINT ["/opt/java/bin/java", "-cp", "/app/proxy.jar", "app.zcat.stargate.runtime.NymLauncher"]
