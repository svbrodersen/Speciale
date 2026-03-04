#!/bin/sh

podman run -it -v .:/workspace:Z -w /workspace custom-riscv-dev
