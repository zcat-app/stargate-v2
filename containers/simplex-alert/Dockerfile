# Inputs prepared and verified by tools/prepare-simplex-alert.sh. No Docker
# socket, shared application state, tools, or credentials are copied here.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS libraries
RUN printf '%s\n' \
    '0ccdfb6d6f5c039465f6d002cf7e4c072d48ac6a2cffc8dd6c748dec31592804  /usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0' \
    '6866ed711dab8927e1bf82bf1cd30e828bdfc34f3cc1e83b1c9eb01ce6c37d9a  /usr/lib/x86_64-linux-gnu/libcrypto.so.3' | sha256sum --check --strict

FROM scratch
COPY rootfs/ /
COPY --from=libraries /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
COPY --from=libraries /usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0 /usr/lib/x86_64-linux-gnu/libgmp.so.10
COPY --from=libraries /usr/share/doc/libgmp10/copyright /usr/share/stargate/simplex-alert/libgmp10-copyright
COPY --from=libraries /usr/share/doc/libssl3t64/copyright /usr/share/stargate/simplex-alert/libssl3t64-copyright
COPY java/ /opt/java/
COPY simplex-chat /opt/simplex/simplex-chat
COPY simplex-alert.jar /opt/simplex/simplex-alert.jar
COPY provenance/ /usr/share/stargate/simplex-alert/
ENV LANG=C.UTF-8 HOME=/profile
USER 10001:10001
WORKDIR /profile
ENTRYPOINT ["/opt/java/bin/java", "-XX:ErrorFile=/dev/null", "-XX:-CreateCoredumpOnCrash", "-cp", "/opt/simplex/simplex-alert.jar", "app.zcat.stargate.simplexalert.SimplexRuntimeMain"]
