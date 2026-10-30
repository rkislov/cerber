FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends samba-ad-dc samba-ad-provision samba-vfs-modules ldap-utils openssl && rm -rf /var/lib/apt/lists/*
COPY entrypoint.py /usr/local/lib/cerber-directory-lab.py
ENTRYPOINT ["/usr/bin/python3", "/usr/local/lib/cerber-directory-lab.py"]
