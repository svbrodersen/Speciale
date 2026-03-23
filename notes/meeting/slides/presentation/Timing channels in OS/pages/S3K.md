# S3K kernel

Real time operating system providing capability based multicore partitioning
for embedded RISC-V systems. 

:: left ::

## Attributes

- Guarantees deterministic process dispatch.
- Temporal partitioning through constant time system calls.
- Protection against timing attacks in the kernel, and timing security for L1
  cache usage.
-- **No protection** in higher level caches.

:: right ::

## Time protection

Makes use of the temporal fence instruction at context switches, which flushing
core-local microarchitectural state.

It is designed to reside entirely within the small scratchpad memory (SPM),
which is backed by core-local L1 cache. This enables the kernel footprint to be
flushed efficiently on domain switch and avoids reliance on larger caches.

All system calls are designed such that all control flow decision and memory
access depend only on data the process is permitted to observe.

