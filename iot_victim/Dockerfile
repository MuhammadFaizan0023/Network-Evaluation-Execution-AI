FROM alpine:3.19

# IoT-device-like services + self-capture tooling
RUN apk add --no-cache \
    busybox-extras \
    dropbear \
    tcpdump \
    curl \
    && mkdir -p /www /pcaps_iot_test

# Minimal landing page so HTTP-based attacks/benign polls get a response
RUN printf '<html><body><h1>NEXA IoT Test Device</h1><p>status: ok</p></body></html>\n' > /www/index.html

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# http, ssh, telnet
EXPOSE 80 22 23

ENTRYPOINT ["/entrypoint.sh"]
