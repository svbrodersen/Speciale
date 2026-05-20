# TODO for Project

## Report — Critical, Must Complete

- [x] **Conclusion** (`sections/conclusion.tex`): Currently empty — only
  `\section{Conclusion}` with no text.
- [x] **Introduction rework**: Add research questions, problem statement,
  thesis outline, and contribution statement. Currently ends abruptly without
  transitions.

## Report — Content Gaps

- [x] **Evaluation — more workloads**: The only workload is the 2-task blinky
  example. Missing: stress tests, multi-domain scenarios, jitter measurements,
  comparison with baseline FreeRTOS.
- [x] **Discussion — underdeveloped**: "Partitioned hardware" and "Viability of
  time protection" subsections exist. Missing: reflection on what worked vs.
  didn't, gap between QEMU and real hardware, when domain scheduling is
  appropriate.
- [ ] **Appendices**: Add full code listings and build/reproduction instructions.
- [x] **Empty `\subsection{Timing channels}`** (`background.tex:101`): Filled with
  a taxonomy of four channel types (scheduler-based, cache-based,
  contention-based, interrupt-based) with sender, shared resource, and receiver
  for each. Serves as a bridge between covert channels and isolation.

## Report — Structural / Polish

- [x] Section overviews: Each section should open with a brief overview of what
  will be presented.
- [ ] Add **List of Figures**, **List of Tables**, **List of Listings**, and
  **Glossary/Abbreviations** in the front matter (after `\tableofcontents`).
