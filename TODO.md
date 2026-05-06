# TODO for Project

- [x] Update Description TODO
- [x] Slides over where we are, what has been done and what is the plan. Include
   information about covert channel and other background material.
- [x] Fix FreeRTOS demo, with plugin.

## Slides
- [x] Create an overview of what is to come in the slides.
- [x] Cut down on the sentence length, bullet points instead.
- [x] Use single column, two pages instead for separations.
- [x] Articles as reference, title should be Background.
- [x] Temporal fence instruction slide
- [x] Move to latex.

## FreeRTOS
- [x] Adding deterministic domain switch with flushing. 
- [x] Fix the xQueue domain event adding back to ready list. Somehow has to track the domain of the item.
- [x] Deterministic timer interrupts.

## QEMU
- [x] How accurate is the cycle?
- [x] Fix FreeRTOS plugin version and test domain scheduler

## User level constant time related work
- [x] Evaluate user level constant time implementations. Why this is insufficient and why it is still needed even in a "safe" OS?


## Report

- [x] Create domain constant time in regards to available information. Create
  some illustration and example of why it is needed with linked lists.
- [x] Figure out missing parts of report, and what else should be added.

- [ ] Exchange the description with an abstract; Explain why I have done what I have done. Explain reasoning, 
- [ ] Overview in each section about what is going to be presented.
- [ ] Specify user level mitigations, that it is not the memory content, but the access address that can be leaked.

- [ ] Read over current sections.

- [ ] Discussion
  - [ ] what is possible
  - [ ] L2 cache 
- [ ] Evaluation
  - [ ] Limitation
  - [ ] Privilege mode making isolation hard.
  - [ ] Example of within domain communication as well as external communication.

- [ ] Future work
- [ ] Conclusion


## Future work

- [ ] Make it simple to create tasks within a domain. Currently cumbersome.
