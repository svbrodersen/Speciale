#!/bin/sh

NAME="speciale"

if podman container exists "$NAME"; then
    podman start -ai "$NAME"
else
    podman run --name "$NAME" -it -v .:/workspace:Z -w /workspace ghcr.io/svbrodersen/speciale:latest
fi
