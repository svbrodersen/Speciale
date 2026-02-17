# Time Protection: The Missing OS Abstraction - Summary Notes

## Paper Overview
**Authors:** Qian Ge, Yuval Yarom, Tom Chothia, Gernot Heiser  
**Published:** EuroSys '19, March 25–28, 2019, Dresden, Germany  
**Key Contribution:** Proposes time protection as a fundamental OS abstraction to prevent timing channels

## Core Problem

### Covert vs. Side Channels
- **Covert Channel:** Requires collusion between sender (Trojan) and receiver
  - Represents worst-case bandwidth scenario
  - Sender intentionally modulates resource usage to transmit information
  
- **Side Channel:** Unwitting sender (victim) leaks information to attacker
  - Example: Malicious VM attacking co-resident VM in cloud
  - Lower bandwidth than covert channels but still dangerous
  - Example: SSL key extraction from web servers

- Result from competition for microarchitectural resources (caches, TLBs, branch predictors, etc.)
- Current OSes provide memory protection (spatial isolation) but lack time protection (temporal isolation)

### Why It Matters
- Cloud computing: VMs from different tenants share physical hardware
- Recent attacks demonstrate practical exploits:
  - Cross-core encryption key extraction via side channels
  - Spectre attacks using covert channels with speculatively executed code
  - Side channels can become covert channels in sophisticated attacks

## Key Concepts

### Microarchitectural Channels

**Two categories of shared resources:**

1. **Microarchitectural State** (stateful resources)
   - Data/instruction caches (L1-D, L1-I, L2, LLC)
   - TLBs (Translation Lookaside Buffers)
   - Branch predictors (BTB, BHB)
   - DRAM row buffers
   - Prefetcher state machines

2. **Stateless Interconnects**
   - Buses and on-chip networks
   - Can be exploited through bandwidth observation
   - No known practical side-channel attacks (only covert channels)

## Time Protection Definition

**Time Protection:** A collection of OS mechanisms that jointly prevent interference between security domains, making execution speed in one domain independent of activities in another.

### Five Core Requirements

**Requirement 1: Flush on-core state**
- When time-sharing a core, flush all on-core microarchitectural state on domain switch
- Includes L1 caches, TLB, branch predictor
- Unless hardware supports partitioning this state

**Requirement 2: Partition the OS**
- Each security domain must have private copy of OS text, stack, and (as much as possible) global data
- Prevents kernel itself from being used as a timing channel

**Requirement 3: Deterministic data sharing**
- Access to any remaining shared OS data must be sufficiently deterministic
- Prevents information leakage through timing variations in kernel operations

**Requirement 4: Flush deterministically**
- State flushing must be padded to worst-case latency
- Prevents cache-flush latency from becoming a channel itself

**Requirement 5: Partition interrupts**
- When sharing a core, disable or partition interrupts (except preemption timer)
- Prevents interrupt timing from leaking information

## Threat Scenarios

### 1. Confinement Scenario
- Preventing Trojan from leaking secrets
- Trojan could be: malicious library, compromised app, server-supplied JavaScript, Spectre gadgets
- Confined component runs in isolated security domain
- **Restriction:** Single core execution or co-scheduled domains (due to interconnect channel limitations)

### 2. Cloud Scenario
- Public cloud hosting mutually-distrusting VMs
- VMs execute concurrently on same processor
- Goal: Prevent side channels (covert channels impossible to prevent with external communication)
- **Restrictions:** 
  - Hyperthreading disabled or all hyperthreads belong to same VM
  - Performance-sensitive (must maximize resource utilization)

## Implementation Approach: Kernel Cloning

### Key Innovation
Instead of static partitioning at boot time, introduce a **policy-free kernel clone mechanism**:
- Creates copy of kernel image in user-supplied memory
- Includes separate stack and replicas of almost all global kernel data
- Allows dynamic creation and destruction of security domains
- Maintains kernel ignorance of specific security policy

### How It Works

1. **Initial Setup:**
   - Boot kernel creates master Kernel_Image capability
   - Initial process partitions memory into colored pools (one per domain)
   - Clones kernel for each domain using domain's memory pool
   - Associates threads with respective kernel images

2. **New Object Types:**
   - **Kernel_Image:** Represents a kernel instance, can be cloned
   - **Kernel_Memory:** Physical memory mappable to kernel image

3. **Shared State Minimization:**
   - Only ~9.5 KiB per core of shared data remains
   - Includes: scheduler queues, IRQ state, ASID table, kernel lock
   - All shared data carefully audited to prevent side channels

### Domain Switch Actions

When switching between domains (on preemption interrupt):

1. Acquire kernel lock
2. Process timer tick normally
3. Mask interrupts
4. **Switch kernel stack** (copies to new stack)
5. Switch thread context (and implicitly kernel image)
6. Release kernel lock
7. Unmask interrupts associated with new kernel
8. **Flush on-core microarchitectural state:**
   - L1-D and L1-I caches
   - TLBs
   - Branch predictor
9. Prefetch shared kernel data (for determinism)
10. **Poll cycle counter for configured latency** (padding)
11. Reprogram timer interrupt
12. Return to user mode

### Cache Flushing Details

**On Arm:**
- L1-D: DCCISW instruction
- L1-I: ICIALLU instruction
- TLB: TLBIALL instruction
- Branch predictor: BPIALL instruction

**On x86:**
- TLB: invpcid instruction
- Branch predictor: IBC (Indirect Branch Control) feature
- L1 caches: "Manual flush" (no direct instruction available)
  - L1-D: Load one word per cache line from buffer
  - L1-I: Sequence of jumps through cache-sized buffer
  - Note: Intel recently added L1-D flush support, but not yet available on test hardware

## Cache Coloring

### Concept
- Large set-associative caches have set-selector bits overlapping with page number
- OS controls which cache "color" (section) a page can occupy
- Partition cache by allocating disjoint colors to different domains

**Formula:** With page size P, cache size S, associativity w:
- Number of colors = S / (w × P)

**Example (Haswell):**
- L2: 256 KiB, 8-way, 4 KiB pages → 8 colors
- LLC: 8 MiB, 16-way, 4 KiB pages → 128 colors

### Limitations
- Cannot color virtually-indexed L1 caches (only 1 color)
- Prevents page sharing between domains (including deduplication)
- Limited number of colors can be bottleneck


## seL4 Integration Advantages

### Why seL4 is Ideal for Time Protection

1. **Memory Management Model:**
   - No kernel heap, bounded stack
   - All dynamic memory provided by userland
   - Kernel metadata stored in user-supplied memory
   - Partitioning user memory automatically partitions kernel data

2. **Capability-Based Security:**
   - All access controlled by capabilities
   - Clean separation of policy and mechanism
   - Formal proofs of spatial isolation already exist

3. **Design for Isolation:**
   - Minimal, policy-free kernel
   - Extensive formal verification
   - Proven absence of covert storage channels

## Evaluation Results

### Test Platforms
- **x86:** Intel Core i7-4770 (Haswell), 4 cores, 3.4 GHz
- **Arm:** i.MX 6Q (Cortex A9), 4 cores, 0.8 GHz

### Timing Channel Mitigation

**Tested channels and results:**

| Channel Type | x86 Raw | x86 Protected | Arm Raw | Arm Protected |
|-------------|---------|---------------|---------|---------------|
| L1-D Cache | 4,000 mb | 0.6 mb | 2,000 mb | 30.2 mb |
| L1-I Cache | 300 mb | 0.8 mb | 2,500 mb | 4.9 mb |
| TLB | 2,300 mb | 16.8 mb | 600 mb | 1.9 mb |
| L2 Cache | 2,700 mb | **50.5 mb** | - | - |
| Kernel Image | 790 mb | 0.6 mb | 20 mb | 0.0 mb |

**Key findings:**
- Most channels effectively closed (< 1 mb, tool resolution limit)
- **x86 L2 residual channel (50 mb):** Due to data prefetcher state not resettable
  - Reduces to 6.4 mb with prefetcher disabled
  - Demonstrates hardware limitation in clearing microarchitectural state
- Cross-core LLC side channel (GnuPG attack): Completely mitigated
- Cache-flush latency channel: Closed with padding
- Interrupt channel: Closed with IRQ partitioning

### Performance Impact

**IPC Microbenchmark:**
- x86: Negligible overhead (~1%)
- Arm: 14-15% overhead (due to loss of global kernel mappings causing TLB conflicts)
  - Expected to improve on Arm v8 with 4-way TLB associativity

**Cache Flush Costs:**
- L1 only (x86): 27 µs direct + indirect
- L1 only (Arm): 45 µs direct + indirect
- Full hierarchy flush much more expensive (520 µs on x86, 1150 µs on Arm)

**Domain Switch Latency:**
- x86: ~30 µs (vs. 271 µs for full flush, 0.18 µs baseline)
- Arm: ~27 µs (vs. 414 µs for full flush, 0.7 µs baseline)
- With 10 ms time slice: ~0.3% overhead

**Application Performance (Splash-2 benchmarks):**
- Most benchmarks: < 2% slowdown with 50% cache colors
- Geometric mean overhead: 3.38% (x86), 1.09% (Arm)
- Includes cache partitioning + kernel cloning + domain switching
- Performance-sensitive workloads with large footprints more affected

**Kernel Operations:**
- Clone kernel: 79 µs (x86), 608 µs (Arm)
  - Much faster than Linux process creation (257 µs / 4,300 µs)
- Destroy kernel: 0.6 µs (x86), 67 µs (Arm)

**Memory Overhead:**
- Per kernel image: ~100 KiB per core
- Includes code, stack, metadata, flush buffers
- Negligible in modern systems

## Hardware Limitations Identified

### Critical Gaps in Hardware Support

1. **No L1 cache flush instructions (x86):**
   - Forced to use expensive "manual flush"
   - Intel recently added L1-D flush but not L1-I
   - Makes flushing unnecessarily expensive

2. **Prefetcher state cannot be reset:**
   - x86 data prefetcher retains history across flushes
   - Leaves residual 50 mb channel in L2
   - Can disable prefetcher but hurts performance

3. **No interconnect partitioning:**
   - No hardware support for bandwidth partitioning on buses
   - Prevents mitigation of cross-core covert channels
   - Intel's MBA (Memory Bandwidth Allocation) insufficient

4. **Arm out-of-order cores:**
   - Prior work showed unflushable microarchitectural state
   - Contains uncloseable high-bandwidth channels
   - Cannot be fixed without hardware changes

### Proposed Hardware-Software Contract

**Requirements for security-oriented ISA:**
1. OS must be able to partition or flush any shared hardware resource
2. Concurrently-accessed resources must be partitionable
3. Virtually-addressed state must be flushable
4. All microarchitectural state must be architecturally visible/controllable

## Key Contributions

1. **Defined time protection** as OS abstraction with clear requirements
2. **Kernel clone mechanism** for policy-free domain partitioning
3. **seL4 implementation** demonstrating feasibility
4. **Empirical evaluation** showing effectiveness and low overhead
5. **Hardware gap analysis** identifying specific ISA deficiencies

## Limitations and Future Work

### Current Limitations
- Requires single-core execution or co-scheduling for confinement (interconnect channel)
- Limited number of cache colors may bottleneck multi-tenant scenarios
- Some hardware platforms have uncloseable channels
- Hyperthreading must be disabled or restricted

### Future Directions
1. Full formal verification of time protection in seL4
2. Integration with temporal integrity mechanisms
3. Better hardware support in future processors
4. Dynamic memory reallocation between domains (balloon drivers)
5. Hierarchical partitioning schemes

## Practical Implications

### For Cloud Providers
- Can provide cryptographically strong isolation between VMs
- Overhead acceptable for security-critical workloads
- May want to offer as premium service
- Requires careful capacity planning (cache colors)

### For System Designers
- Time protection should be considered alongside memory protection
- Highlights importance of hardware-software co-design for security
- Need for ISA evolution to support temporal isolation

### For Security Researchers
- Demonstrates timing channels are solvable problem (with right hardware)
- Provides framework for analyzing future microarchitectural channels
- Shows value of formal methods combined with empirical evaluation

## Methodology Notes

### Mutual Information (MI) Analysis
- Measures average bits of information leaked per channel use
- Treats time measurements as probability density functions
- Uses kernel density estimation from large sample sets
- Statistical test distinguishes real leakage from sampling noise
  - Shuffling test with 100 iterations
  - 95% confidence interval (M vs M₀)
  - M > M₀ indicates definite channel
- Tool resolution: ~1 millibit (negligible threshold)

## Related Work Context

- **Deterministic systems** (Determinator, Stopwatch): Virtual time prevents channels but heavy overhead
- **Page coloring**: Proposed for performance/real-time, adapted here for security
- **Hardware partitioning**: Intel CAT, Arm cache locking - insufficient alone
- **Multikernel/Corey/Helios**: Per-core kernels for performance, not security
- **seL4 proofs**: Existing spatial isolation proofs foundation for temporal isolation

## Conclusion

Time protection represents a fundamental shift in OS security architecture, elevating temporal isolation to the same level of importance as spatial isolation. The work demonstrates:

1. **Feasibility:** Time protection can be implemented with acceptable overhead
2. **Effectiveness:** Can close most timing channels on current hardware
3. **Necessity:** Hardware improvements needed for complete solution
4. **Generality:** Approach applicable beyond seL4 (though easier in microkernels)

The paper makes a compelling case that time protection should become standard OS security mechanism, just as memory protection is today. Success requires both better OS mechanisms (demonstrated here) and improved hardware support (advocacy ongoing).
