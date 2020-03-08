#!/bin/sh

TAG=proelbtn/etherip

docker run -it --rm --name etherip \
  --privileged \
  --net host \
  -v /lib/modules/$(uname -r):/lib/modules/$(uname -r) \
  -v /usr/src/linux-headers-$(uname -r | sed "s:-generic::"):/usr/src/linux-headers-$(uname -r | sed "s:-generic::") \
  -v /usr/src/linux-headers-$(uname -r):/usr/src/linux-headers-$(uname -r) \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug \
  ${TAG}
