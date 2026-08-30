FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Update and install all penetration testing tools in one layer
RUN apt-get update -q && apt-get install -y \
    nmap \
    dirb \
    dirbuster \
    seclists \
    curl \
    wget \
    gobuster \
    nikto \
    ffuf \
    hydra \
    sqlmap \
    whatweb \
    masscan \
    medusa \
    wfuzz \
    netcat-openbsd \
    enum4linux \
    dnsutils \
    whois \
    iputils-ping \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Verify key tools are installed
RUN which nmap && which curl && which gobuster && nmap -V

WORKDIR /workspace
