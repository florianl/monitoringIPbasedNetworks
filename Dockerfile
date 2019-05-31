FROM fedora:30

RUN dnf update -y

RUN dnf install -y golang git

ENV GO111MODULE=on

# Dependency for libpcap example
RUN dnf install -y libpcap-devel

# Dependency for eBPF/[trafficControl|tracepoint|xdp] example
# RUN dnf install -y bcc-devel

# Basic network utilities to setup a demo environment
RUN dnf install -y iproute iputils

# Fetch this repository
RUN cd /tmp/ \
    && git clone https://github.com/florianl/monitoringIPbasedNetworks.git

# Fetch dependencies and install all binaries
RUN cd /tmp/monitoringIPbasedNetworks \
    && go mod download \
    && cd libpcap/ && go install ./...

ENV PATH="/root/go/bin:${PATH}"

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/bash"]
