# The missing OS abstraction: sel4

Attempt to close all possible covert channels, arguing that closing covert
channels closes timing channels.

:: left ::

## Time protection

A collection of OS mechanism which jointly prevent interference between
security domains that would make execution speed in one domain dependent on the
activities of another.

Partitioning comes in two forms:
- **Spatial partitioning**: Separate memory and resources between domains, such that it is not shared.
- **Temporal partitioning**: Resetting a state to a known default, e.g. flushing.

:: right ::

## Requirements for Time Protection

* Flush on-core state on domain switch in a deterministic manner.
* Partition the OS, e.g. syscalls.
  - Spatially, kernel data separated from user data.
  - Temporally, set shared OS state to a known default when finishing syscalls.
  - Interrupts must also follow same criteria.
* Deterministic data sharing, e.g. for message sending.

## Implementation

Using kernel clone, to clone OS code into each domain.
Deterministic context switch with flushing.
Cache coloring.

