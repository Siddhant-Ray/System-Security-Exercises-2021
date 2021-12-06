#!/bin/bash

cd Enclave_A/ && make clean
make SGX_MODE=SIM
./app &

cd ..
cd Enclave_B/ && make clean
make SGX_MODE=SIM
./app &

exit
