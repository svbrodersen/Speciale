# QEMU TCG plugin

A missing platform for quick development and evaluation.

:: left ::

## QEMU

QEMU provides cross platform full system emulation, allowing for running of
kernels on an arbitrary host machine.

Cross platform emulation happens through the Tiny Code Generator(TCG) layer,
which translates guest CPU instructions into host CPU instructions.

## TCG plugin

Recently QEMU provides support for TCG plugins, which can register hooks for a
lot of the TCG api, e.g. memory access and instruction translation.

:: right ::

## Cache emulation

By registering hooks on memory access and instruction translations, I have
created a plugin for emulating cache state. This registers data hits/misses as
well as instruction hit/misses.

## Timing detection

The plugin allows for extensions, which return the currently running domain for
each instruction to detect cross domain evictions.

Implement temporal fence through the specific noop instruction `addi x0, x0, 11
= 0x00b00013`.






