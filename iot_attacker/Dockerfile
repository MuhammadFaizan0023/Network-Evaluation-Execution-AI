FROM kalilinux/kali-rolling

# Tools needed by the iot_attacks/*.sh scenarios.
# (mitm_iot.sh uses arpspoof from dsniff; ettercap intentionally omitted to keep
#  the image small and the build fast.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    slowhttptest \
    hping3 \
    curl \
    netcat-traditional \
    dsniff \
    dnsutils \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# IoT attack scripts are mounted here at runtime
WORKDIR /iot_attacks

# Keep container running; attacks are launched via `docker exec`
CMD ["tail", "-f", "/dev/null"]
