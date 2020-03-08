# syntax=docker/dockerfile:experimental
FROM fedora:30

RUN --mount=type=cache,target=/var/cache/dnf dnf install -y bcc bpftool clang iproute kmod python3-pip

RUN pip3 install grpcio-tools poetry pyroute2

RUN mkdir -p /opt/etherip
WORKDIR /opt/etherip

COPY src/python/* /opt/etherip
COPY src/clang/* /opt/etherip

ENTRYPOINT [ "python3", "./main.py" ]
