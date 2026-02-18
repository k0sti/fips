FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping dnsutils openssh-client openssh-server iperf3 && \
    rm -rf /var/lib/apt/lists/*

# Setup SSH server with no authentication (test only!)
RUN mkdir -p /var/run/sshd && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    passwd -d root

COPY fips /usr/local/bin/
RUN chmod +x /usr/local/bin/fips

# Start SSH server and iperf3 server in background, then run FIPS
ENTRYPOINT ["/bin/bash", "-c", "/usr/sbin/sshd && iperf3 -s -D && exec fips --config /etc/fips/fips.yaml"]
