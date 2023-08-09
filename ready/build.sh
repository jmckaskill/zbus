#!/bin/sh
musl-gcc -static -o fifo-ready -O2 -DNDEBUG fifo-ready.c
musl-gcc -static -o fifo-check -O2 -DNDEBUG fifo-check.c