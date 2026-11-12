# SPDX-License-Identifier: Apache-2.0
# Pinned multi-platform index: linux/amd64 and linux/arm64, Suricata 8.0.3.
FROM jasonish/suricata:8.0.3@sha256:3f7b2f06e4667e4149deb34c52f278213a4a9b74bf926939aa5cbfc6c595dca0
RUN /usr/bin/suricata -V | grep -F '8.0.3' && test -x /usr/sbin/ip \
    && chmod 0755 /etc/suricata && chmod 0644 /etc/suricata/*.config /etc/suricata/suricata.yaml
COPY cerber-sensor /usr/local/bin/cerber-sensor
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/cerber-sensor"]
