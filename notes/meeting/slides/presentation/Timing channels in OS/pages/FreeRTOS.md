# FreeRTOS

An industry used real time operating system.

:: left ::

## What is it?

FreeRTOS is a real time operating system.
It does not take timing channels into account, and only supports memory
protection on ARM through MPU.
Highly configurable, and used in a lot of microcontrollers and small microprocessors.
Supported on more than 40+ MCU architectures.

## Domains in FreeRTOS

In the single core configuration, FreeRTOS stores the current Task Control
Block(TCB) in a global variable `pxCurrentTCB`. Each TCB contains a unique id,
which is used for domain for the plugin.


:: right ::

## Current work

- [ ] Adding deterministic domain switch with flushing. 
- [ ] Deterministic timer interrupts.
- [ ] Deterministic data sharing through Queues.
- [ ] Partitioning the OS.

Can timing protection be implemented in FreeRTOS with minimal overhead?
What is required in terms of hardware support, and are there aspects that seem infeasible to protect against?
If so, what can be protected against, and what remains unprotected?





