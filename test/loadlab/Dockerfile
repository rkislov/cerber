FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends suricata ca-certificates iproute2 python3 && rm -rf /var/lib/apt/lists/*
COPY cerber cerber-sensor seed /usr/local/bin/
