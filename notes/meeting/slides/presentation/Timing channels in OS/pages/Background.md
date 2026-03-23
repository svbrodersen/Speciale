# Background

:: left ::

## Attack front

Timing channels exploit the physical execution of software. An attack can
observe execution time and infer sensitive information about another domain.

Timing channels violate intended isolation boundaries and have been shown to be
potent in the Spectre and Meltdown attacks.

Constant time programming by the user does not guarantee security, as the
kernel can inadvertently still leak information during syscalls and context switching.

:: right ::

- **Side channels**: are unintended information channels, that leak information about
a domain inadvertently. This happens during normal program execution.

- **Covert channels**: are collaborative domains attempting to communicate via.
unintended channels. Usually involves a sender (Trojan) and a receiver (Spy),
where the sender is able to access high security, but restricted in
communication with the receiver.


