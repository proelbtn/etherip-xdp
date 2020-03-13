#!/bin/sh

sudo echo -n

sudo apt install -y \
	linux-buildinfo-5.3.0-23-generic \
	linux-headers-5.3.0-23-generic \
	linux-image-5.3.0-23-generic \
	linux-modules-5.3.0-23-generic \
	linux-modules-extra-5.3.0-23-generic \
	linux-tools-5.3.0-23-generic

if ! which docker >/dev/null 2>&1; then
  curl -L get.docker.com | sudo sh
  sudo usermod -aG docker $(id -un)
fi

