# Reproducibility container for the NetProbe paper experiments.
#   docker build -t netprobe-repro .
#   docker run --rm --privileged -v "$PWD":/src netprobe-repro bash examples/run_reproduce_paper.sh
# --privileged is needed to create network namespaces and attach tc netem.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping iperf3 ethtool tcpdump procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -e ".[plot,dev]"
CMD ["bash"]
