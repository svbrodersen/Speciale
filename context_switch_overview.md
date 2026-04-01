# Context switch overview

## Notes:
  (constant) is in regards to branching based on secrets. Cache and architecture state must be empirically measured.

- freertos_risc_v_mtimer_interrupt_handler
  - Save state (constant)
  - update MTimer Compare (constant)
  - call xTaskIncrementTick 
  - Switch needed?
    - yes
      - Call vTaskSwitchContext
  - Restore interrupt context
  - return

- xTaskIncrementTick
  - is Scheduler suspended?
    - No
      - increment tick
      - xConstTickCount >= xNextTaskUnblock?
        - loop until all ready tasks are placed into ready lists
        - higher priority -> switch required
      - If other tasks exist of same priority, then switch required (constant).
    - yes
      - increment tick
  

## Overview

### Protection within same priority, no protection outside

### Full protection, constant amount of time slices, more allocated to higher priority tasks

### Full protection, constant amount of time slices, allocate to time slice based on creation

  - Going to sleep makes idle task run instead of one self. When execution is finished, then a new task can be scheduled in the time slot.

### No time available for tasks



