FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
RUN apt-get update && apt-get install -y --no-install-recommends g++ make libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libboost-json-dev libboost-url-dev libssl-dev zlib1g-dev libminiupnpc-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /source
