#!/bin/sh

TAG=proelbtn/etherip

cd $(dirname $0)/..

DOCKER_BUILDKIT=1 docker build -t ${TAG} .
