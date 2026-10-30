FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends suricata ca-certificates && rm -rf /var/lib/apt/lists/*
COPY cerber-sensor /usr/local/bin/cerber-sensor
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/cerber-sensor"]
