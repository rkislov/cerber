FROM scratch
COPY cerber-sensor /cerber-sensor
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 1000:1000
ENTRYPOINT ["/cerber-sensor"]
