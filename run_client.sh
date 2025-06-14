#!/bin/bash

# python3 -m venv grpc_env
# source grpc_env/bin/activate
# pip install protobuf grpcio grpcio-tools grpcio-status

python -m venv grpc_env_clean
source grpc_env_clean/bin/activate
pip install --upgrade pip
# pip install grpcio grpcio-tools grpcio-status
pip install protobuf 
pip install grpcio-tools
pip install grpcio-status
pip install grpcio
sudo python3 filemonitor.py