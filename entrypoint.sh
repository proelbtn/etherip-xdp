#!/bin/sh

mount bpffs /sys/fs/bpf -t bpf

python3 main.py
