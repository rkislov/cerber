# SPDX-License-Identifier: Apache-2.0
# Ubuntu retains support for baseline x86_64 CPUs, unlike x86-64-v2 images.
FROM ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5
ARG TARGETARCH
# Exact OISF stable PPA packages, checked against its noble Packages index.
RUN set -eu; apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl iproute2 libtcmalloc-minimal4t64; \
    case "$TARGETARCH" in \
      amd64) digest=05f95312d46e61f6e3c0dea5c94f16da037b72ecee3502b2d8436a5b804a6883 ;; \
      arm64) digest=441098339179dccafda358fd66c2a39a25a9068e123afb390bf8971769f24244 ;; \
      *) exit 1 ;; \
    esac; \
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      "https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu/pool/main/s/suricata/suricata_8.0.8-0ubuntu0_${TARGETARCH}.deb" -o /tmp/suricata.deb; \
    printf '%s  /tmp/suricata.deb\n' "$digest" | sha256sum -c -; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends /tmp/suricata.deb; \
    /usr/bin/suricata -V | grep -F '8.0.8'; \
    chmod 0755 /etc/suricata; chmod 0644 /etc/suricata/*.config /etc/suricata/suricata.yaml; \
    rm -f /tmp/suricata.deb; rm -rf /var/lib/apt/lists/*
COPY cerber-sensor /usr/local/bin/cerber-sensor
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/cerber-sensor"]
