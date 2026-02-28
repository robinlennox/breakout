FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    openssh-server \
    openssh-client \
    sudo \
    wireless-tools \
    iproute2 \
    net-tools \
    netcat-openbsd \
    wget \
    ca-certificates \
    procps \
    rfkill \
    gcc \
    iodine \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH daemon directory
RUN mkdir -p /run/sshd

# Install udp2raw (client)
RUN wget -q https://github.com/wangyu-/udp2raw-tunnel/releases/download/20181113.0/udp2raw_binaries.tar.gz -P /tmp \
    && tar -xf /tmp/udp2raw_binaries.tar.gz -C /usr/local/bin/ udp2raw_amd64 \
    && mv /usr/local/bin/udp2raw_amd64 /usr/local/bin/udp2raw \
    && chmod +x /usr/local/bin/udp2raw \
    && rm -f /tmp/udp2raw_binaries.tar.gz

# Install kcptun (client)
RUN wget -q https://github.com/iaineng/kcptun/releases/download/v20260129/kcptun_linux_amd64.tar.gz -P /tmp \
    && tar -xf /tmp/kcptun_linux_amd64.tar.gz -C /usr/local/bin/ client_linux_amd64 \
    && mv /usr/local/bin/client_linux_amd64 /usr/local/bin/kcptun_client \
    && chmod +x /usr/local/bin/kcptun_client \
    && rm -f /tmp/kcptun_linux_amd64.tar.gz

# Install breakout
WORKDIR /opt/breakout
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .
RUN mkdir -p logs configs \
    && touch configs/ignore_ssid

# Start SSH daemon and breakout
RUN echo '#!/bin/bash\n/usr/sbin/sshd\nexec python3 breakout.py "$@"' > docker-entrypoint.sh \
    && chmod +x docker-entrypoint.sh

ENTRYPOINT ["/opt/breakout/docker-entrypoint.sh"]
CMD ["-h"]
