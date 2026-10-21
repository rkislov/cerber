FROM scratch
COPY cerber /cerber
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 1000:1000
ENTRYPOINT ["/cerber"]
