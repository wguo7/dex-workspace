FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    cron \
    systemd \
    inotify-tools \
    at \
    logrotate \
    udev \
    sudo \
    bash \
    coreutils \
    procps \
    rsyslog \
    libpam-modules \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["/bin/bash"]
