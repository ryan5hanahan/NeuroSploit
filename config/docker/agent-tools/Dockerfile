# Docker image for LLM-driven agent's shell tool execution.
# Includes common pentesting tools pre-installed for fast execution.
#
# Build: docker build -t sploitai-agent-tools -f config/docker/agent-tools/Dockerfile .
# Usage: Used by shell_tool.py for sandboxed command execution.

# -- Stage 1: Go tool compilation --
FROM golang:1.22-bookworm AS go-builder

ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:${PATH}"

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/hahwul/dalfox/v2@latest

# -- Stage 2: Runtime image --
FROM python:3.11-slim-bookworm

# Install system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    curl \
    wget \
    git \
    jq \
    dnsutils \
    whois \
    netcat-openbsd \
    openssl \
    libpcap-dev \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Install sqlmap from pip
RUN pip install --no-cache-dir sqlmap

# Install feroxbuster
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin

# Install whatweb
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

# Install wafw00f
RUN pip install --no-cache-dir wafw00f

# Install Playwright for browser automation
RUN pip install --no-cache-dir playwright && \
    playwright install chromium --with-deps

# Copy Go tools from builder
COPY --from=go-builder /root/go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /root/go/bin/httpx /usr/local/bin/
COPY --from=go-builder /root/go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /root/go/bin/naabu /usr/local/bin/
COPY --from=go-builder /root/go/bin/katana /usr/local/bin/
COPY --from=go-builder /root/go/bin/gobuster /usr/local/bin/
COPY --from=go-builder /root/go/bin/ffuf /usr/local/bin/
COPY --from=go-builder /root/go/bin/dalfox /usr/local/bin/

# Create non-root user for security
RUN useradd -m -s /bin/bash -u 1000 agent
RUN mkdir -p /home/agent/output /home/agent/wordlists && \
    chown -R agent:agent /home/agent

# Copy common wordlists
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -sL -o /usr/share/wordlists/dirb/common.txt \
    https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD nmap --version && nuclei --version

USER agent
WORKDIR /home/agent

CMD ["tail", "-f", "/dev/null"]
