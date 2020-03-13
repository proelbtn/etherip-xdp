#!/bin/sh

TAG=proelbtn/etherip

cd $(dirname $0)/..

python -m grpc_tools.protoc -I./src/protos --python_out=./src/python --grpc_python_out=./src/python ./src/protos/etherip.proto

DOCKER_BUILDKIT=1 docker build -t ${TAG} .

