# TODO for Project

## Report — Critical, Must Complete

- [ ] **Conclusion** (`sections/conclusion.tex`): Currently empty — only
  `\section{Conclusion}` with no text.
- [ ] **Introduction rework**: Add research questions, problem statement,
  thesis outline, and contribution statement. Currently ends abruptly without
  transitions.
- [ ] **Threat model**: Define a formal threat model for FreeRTOS domains
  (attacker capabilities, trust assumptions, what is in/out of scope).
- [ ] **Methodology section**: No explicit description of research approach,
  experimental design, or methodology framing exists.
  - Describe the overall research approach: literature review, design space
    exploration (analysis of scheduling approaches), implementation (code
    modifications to FreeRTOS-MPU), and evaluation (QEMU-based testing)
  - Specify the tools and environment: QEMU system emulation (`-icount` flag),
    RISC-V toolchain, FreeRTOS-MPU community port, `rdcycle`/`rdcycleh` for
    cycle counting
  - Explain the experimental design: the blinky example as a functional test,
    the round-trip cycle measurement as a timing test, and the limitations of
    the QEMU platform
  - Frame how the evaluation connects back to the research questions — what is
    being measured and why

## Report — Content Gaps

- [ ] **Evaluation — more workloads**: The only workload is the 2-task blinky
  example. Missing: stress tests, multi-domain scenarios, jitter measurements,
  comparison with baseline FreeRTOS.
- [ ] **Discussion — underdeveloped**: "Partitioned hardware" and "Viability of
  time protection" subsections exist. Missing: reflection on what worked vs.
  didn't, gap between QEMU and real hardware, when domain scheduling is
  appropriate.
- [ ] **Appendices**: Add full code listings (domain creation, QEMU plugin,
  config flags), and build/reproduction instructions.

## Report — Structural / Polish

- [ ] Section overviews: Each section should open with a brief overview of what
  will be presented.
- [ ] Add List of Figures, List of Tables, List of Listings, and
  Glossary/Abbreviations.
- [ ] Background: currently jumps from side-channels/covert channels straight
  to `fence.t` and FreeRTOS. Missing:
  - **Taxonomy of timing channels in OS kernels**: distinguish between channel
    types by mechanism — scheduler-based channels (priority inversion,
    starvation, jitter), cache-based channels (Flush+Reload, Prime+Probe,
    Evict+Time), contention-based channels (shared functional units, buses,
    memory arbiters), and interrupt-based channels. For each: who is the
    sender, what shared resource is modulated, and how the receiver observes
    the modulation.
  - **How other OS schedulers handle timing isolation**: fixed-priority
    preemptive (FreeRTOS default) inherently leaks information through priority
    ordering; time-slice based scheduling (static partitions) prevents
    cross-partition leakage but at the cost of utilization; hierarchical
    scheduling (domains containing sub-schedulers) is the approach used by
    seL4/S3K. Situate this thesis's domain scheduler within this landscape.
  - **RISC-V privilege levels and FreeRTOS-MPU mapping**: explain Machine mode
    (M), Supervisor mode (S), User mode (U), and how FreeRTOS-MPU uses M-mode
    for the kernel and U-mode for tasks. How the PMP (Physical Memory
    Protection) unit enforces spatial isolation. How machine timer interrupts
    drive the scheduler from M-mode, and why this architecture influences the
    domain switching design.
