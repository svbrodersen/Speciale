# The missing OS abstraction: sel4

Attempt to close all possible covert channels, arguing that closing covert
channels closes timing channels.

:: left ::

## Time protection

A collection of OS mechanism which jointly prevent interference between
security domains that would make execution speed in one domain dependent on the
activities of another.

Partitioning comes in two forms:
- **Temporal partitioning**: Resetting a state to a known default, e.g. flushing.
- **Spatial partitioning**: Separate resources between domains, such that it is not shared.


:: right ::

## Requirements for Time Protection

* Flush on-core state on domain switch.
* Partition the OS
* Deterministic data sharing
* Flush deterministically
* Partition interrupts

## Implementation

Using kernel clone, to clone OS code into each domain.
Deterministic context switch with flushing.
Cache coloring.

