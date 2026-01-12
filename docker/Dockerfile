# cl-hive Production Node
# Core Lightning + Tor + WireGuard + Full Plugin Stack
#
# Build: docker build -t cl-hive-node .
# Run:   docker-compose up -d

FROM ubuntu:24.04

LABEL maintainer="Lightning Goats Team"
LABEL version="0.1.0-dev"
LABEL description="Production Lightning node with cl-hive coordination"

# Prevent interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# =============================================================================
# SYSTEM PACKAGES
# =============================================================================

RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git \
    curl \
    wget \
    # Core Lightning dependencies
    libgmp-dev \
    libsqlite3-dev \
    python3 \
    python3-pip \
    python3-venv \
    net-tools \
    zlib1g-dev \
    libsodium-dev \
    gettext \
    # Tor
    tor \
    # WireGuard
    wireguard \
    wireguard-tools \
    # Networking utilities
    iproute2 \
    iptables \
    dnsutils \
    # Process management
    supervisor \
    # JSON processing
    jq \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# CORE LIGHTNING
# =============================================================================

# Install Core Lightning from official repository
RUN curl -fsSL https://apt.lightning.engineering/keys/cln-signing-key.gpg | gpg --dearmor -o /usr/share/keyrings/cln-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cln-archive-keyring.gpg] https://apt.lightning.engineering/ubuntu noble main" > /etc/apt/sources.list.d/cln.list \
    && apt-get update \
    && apt-get install -y core-lightning \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# PYTHON ENVIRONMENT
# =============================================================================

# Create virtual environment for plugins
RUN python3 -m venv /opt/cln-plugins-venv
ENV PATH="/opt/cln-plugins-venv/bin:$PATH"

# Install Python dependencies
RUN pip install --no-cache-dir \
    pyln-client>=24.0 \
    requests \
    anthropic

# =============================================================================
# CLBOSS (ksedgwic fork with clboss-unmanage support)
# =============================================================================

WORKDIR /tmp

RUN apt-get update && apt-get install -y \
    libev-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/ksedgwic/clboss.git \
    && cd clboss \
    && autoreconf -i \
    && ./configure \
    && make -j$(nproc) \
    && make install \
    && cd .. \
    && rm -rf clboss

# =============================================================================
# SLING PLUGIN
# =============================================================================

RUN ARCH=$(uname -m) \
    && if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi \
    && if [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi \
    && wget -O /usr/local/bin/sling "https://github.com/daywalker90/sling/releases/latest/download/sling-${ARCH}" \
    && chmod +x /usr/local/bin/sling

# =============================================================================
# CL-REVENUE-OPS PLUGIN
# =============================================================================

RUN git clone --depth 1 https://github.com/santyr/cl-revenue-ops.git /opt/cl-revenue-ops \
    && chmod +x /opt/cl-revenue-ops/cl-revenue-ops.py

# =============================================================================
# CL-HIVE PLUGIN
# =============================================================================

COPY . /opt/cl-hive
RUN chmod +x /opt/cl-hive/cl-hive.py

# =============================================================================
# TOR CONFIGURATION
# =============================================================================

RUN mkdir -p /var/lib/tor/cln-service \
    && chown -R debian-tor:debian-tor /var/lib/tor

COPY docker/torrc /etc/tor/torrc

# =============================================================================
# DIRECTORY STRUCTURE
# =============================================================================

RUN mkdir -p /root/.lightning/bitcoin \
    && mkdir -p /root/.lightning/plugins \
    && mkdir -p /data/lightning \
    && mkdir -p /data/bitcoin

# Symlink plugins to CLN plugins directory
RUN ln -sf /opt/cl-hive/cl-hive.py /root/.lightning/plugins/cl-hive.py \
    && ln -sf /opt/cl-hive/modules /root/.lightning/plugins/modules \
    && ln -sf /opt/cl-revenue-ops/cl-revenue-ops.py /root/.lightning/plugins/cl-revenue-ops.py \
    && ln -sf /opt/cl-revenue-ops/modules /root/.lightning/plugins/revenue-modules \
    && ln -sf /usr/local/bin/clboss /root/.lightning/plugins/clboss \
    && ln -sf /usr/local/bin/sling /root/.lightning/plugins/sling

# =============================================================================
# CONFIGURATION FILES
# =============================================================================

COPY docker/docker-entrypoint.sh /usr/local/bin/
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/lightning.conf.template /etc/lightning/lightning.conf.template
COPY cl-hive.conf.sample /etc/lightning/cl-hive.conf

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# =============================================================================
# PORTS
# =============================================================================

# Lightning P2P
EXPOSE 9735
# Lightning REST API
EXPOSE 8080
# Tor SOCKS (internal)
EXPOSE 9050
# WireGuard
EXPOSE 51820/udp

# =============================================================================
# VOLUMES
# =============================================================================

VOLUME ["/data/lightning", "/data/bitcoin", "/etc/wireguard"]

# =============================================================================
# ENTRYPOINT
# =============================================================================

WORKDIR /root

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
