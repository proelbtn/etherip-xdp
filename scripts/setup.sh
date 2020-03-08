#!/bin/sh

sudo echo -n

if ! which docker >/dev/null 2>&1; then
  curl -L get.docker.com | sudo sh
  sudo usermod -aG docker $(id -un)
fi

