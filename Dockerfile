FROM debian:trixie-slim

ENV HOSTNAME="breakout"
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

# Setup SSH daemon directory and breakout user
RUN mkdir -p /run/sshd \
    && useradd -m -s /bin/bash breakout \
    && mkdir -p /home/breakout/.ssh \
    && chown -R breakout:breakout /home/breakout/.ssh \
    && chmod 700 /home/breakout/.ssh
    
# Install udp2raw (client)
RUN wget -q https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -P /tmp \
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

# Configure SSH daemon and breakout
RUN echo 'breakout:passwd' | chpasswd \
    && sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && printf "%b\n" '#!/bin/bash\nmkdir -p /run/sshd\nssh-keygen -A >/dev/null 2>&1\n/usr/sbin/sshd -D -e > /var/log/sshd.log 2>&1 &\nexec python3 breakout.py "$@"' > docker-entrypoint.sh \
    && chmod +x docker-entrypoint.sh

ENTRYPOINT ["/opt/breakout/docker-entrypoint.sh"]
CMD ["-h"]
