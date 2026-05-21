# Eliminating Timing Channels in Microkernels

Master's thesis investigating the feasibility of integrating time protection
mechanisms into FreeRTOS to mitigate timing channels. The project implements a
**domain-level scheduler** that partitions execution into fixed time slices,
ensuring that tasks in one domain cannot observe or affect the timing of tasks
in another. On domain switches the `fence.t` instruction is used to clear
shared microarchitectural state.

## Repository structure

| Path            | Description                                                  |
|-----------------|--------------------------------------------------------------|
| `report/`       | LaTeX source for the thesis report                           |
| `src/FreeRTOS/` | Modified FreeRTOS-MPU RISC-V port (submodule)                |
| `src/qemu/`     | QEMU fork used for emulation (submodule)                     |
| `src/qemu_timing_plugin/` | QEMU TCG plugin for cache modelling experiments  |
| `src/s3k/`      | S3K real-time operating system (related work, submodule)     |
| `src/sentry-kernel/` | Sentry microkernel (related work, submodule)             |
| `notes/`        | Meeting notes and background research                        |
| `podman.sh`     | Container setup script (see below)                           |

## Quick start with Podman

The repository includes a pre-built container image with all required
dependencies (RISC-V GNU toolchain, QEMU system emulator). To enter the
container:

```bash
./podman.sh
```

This pulls the image `ghcr.io/svbrodersen/speciale:latest` and mounts the
repository into `/workspace` inside the container. If the container already
exists, it resumes it.

## Building and running the demos

All commands below must be run inside the container. Once connecting to the
container you should immediately start in the direcotry
"/workspace/src/FreeRTOS/FreeRTOS/Demo/ThirdParty/Community-Supported-Demos/RISC-V_RV32_MPU_QEMU_VIRT_GCC/"

### Build

```bash
make -C build/gcc
```

The ELF binary is produced at `build/gcc/output/RTOSDemo.elf` inside that
directory.

### Run

Standard execution (host-clock-based timing):
```bash
make -C build/gcc qemu-run
```

Deterministic instruction-counting mode (for constant-time evaluation):
```bash
make -C build/gcc qemu-timing
```

Debug mode (QEMU waits for GDB on port 1234):
```bash
make -C build/gcc qemu-debug
```

When launching in debug, you have to connect a secondary terminal to the
container via. "podman exec -it speciale /bin/bash", and then run the
specialized gdb as follows:

```
riscv64-unknown-elf-gdb ./build/gcc/output/RTOSDemo.elf
```

### Switching between demos

Edit `src/FreeRTOS/FreeRTOS/Demo/ThirdParty/Community-Supported-Demos/RISC-V_RV32_MPU_QEMU_VIRT_GCC/main.c`
(line 134-136). The available demos are:

| Function         | File              | Description                                                          |
|------------------|-------------------|----------------------------------------------------------------------|
| `domain_full()`  | `domain_full.c`   | 4 domains each with privileged/unprivileged tasks (active by default), The configNUM_TIME_SLICES should be 10 for this demo |
| `mpu_blinky()`   | `mpu_blinky.c`    | Cross-domain sender/receiver with queue communication                 |
| `main_blinky()`  | `main_blinky.c`   | Simple queue-based blinky (no MPU, no domains), the configNUM_TIME_SLICES should be 6 for this demo                       |
| `main_full()`    | `main_full.c`     | Comprehensive FreeRTOS test suite (set `mainCREATE_SIMPLE_BLINKY_DEMO_ONLY` to 0) |


### Key configuration flags

Defined in `FreeRTOSConfig.h`:

| Flag                        | Description                                      | Default |
|-----------------------------|--------------------------------------------------|---------|
| `configENABLE_DOMAINS`      | Enable the domain-level scheduler                | 1       |
| `configNUM_TIME_SLICES`     | Total time slices (also max number of domains)   | 10      |
| `configNUM_TICKS_PER_SLICE` | Timer ticks per time slice                       | 1       |

## mpu_blinky example

Creates two unprivileged tasks (Sender and Receiver) in separate domains
communicating via a FreeRTOS Queue. The sender sends messages each tick; the
receiver prints them. On the 5th iteration the sender intentionally accesses
privileged memory, triggering a PMP access fault to demonstrate memory
protection.

## domain_full example

Creates 4 domains, each with a privileged task that spawns an unprivileged
child. The unprivileged tasks monitor and print their domain tick, showing that
each domain runs in its allocated time slice round-robin. With `-icount` mode
the round-trip time per domain is constant (variance of ~1 instruction count).

## License

See the respective submodules for their licenses. The FreeRTOS kernel is
distributed under the MIT license.
