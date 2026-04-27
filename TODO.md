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
- [ ] Deterministic timer interrupts.

## QEMU
- [ ] How accurate is the cycle?
- [ ] Fix FreeRTOS plugin version and test domain scheduler

## User level constant time related work
- [ ] Evaluate user level constant time implementations. Why this is insufficient and why it is still needed even in a "safe" OS?
- [ ] Tools for showing timing channel. dudect, why the plugin is needed for OS evaluation.


