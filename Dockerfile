# syntax=docker/dockerfile:experimental
FROM fedora:30

RUN --mount=type=cache,target=/var/cache/dnf dnf install -y bcc bpftool clang iproute kmod python3-pip

RUN pip3 install poetry pyroute2

