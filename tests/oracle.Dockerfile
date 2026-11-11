# The oracle's reference Linux: real kernel, same userland as linuxity's
# "ubuntu" environment. Build once, then run the oracle against it:
#   docker build -t lx-oracle -f tests/oracle.Dockerfile tests
#   docker run --privileged --rm -v "$PWD/tests:/mnt/t:ro" lx-oracle
FROM ubuntu:24.04
RUN export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && \
    apt-get install -y -qq python3 procps xz-utils tzdata make perl locales && \
    rm -rf /var/lib/apt/lists/*
CMD ["python3", "/mnt/t/oracle.py"]
