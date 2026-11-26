    .text
    .globl _start
_start:
    pushl $0
    calll *"__imp__ExitProcess@4"
