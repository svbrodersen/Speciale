#!/bin/sh

podman run -it --rm -v .:/workspace:Z -w /workspace custom-riscv-dev
