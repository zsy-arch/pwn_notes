#!/bin/bash

DIR=/home/zsy/pwn/glibc-all-in-one/libs/2.31-0ubuntu9.16_amd64
LD_NAME=ld-linux-x86-64.so.2

gcc pwn.c -o pwn -g

patchelf --set-interpreter ${DIR}/${LD_NAME} ./pwn
patchelf --set-rpath ${DIR}/ ./pwn

cp ${DIR}/libc.so.6 .
