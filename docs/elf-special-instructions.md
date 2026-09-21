# ELF x86 special instructions

The Instruction sets analysis for ELF32/i386 and ELF64/x86-64 includes the same
special-instruction categories and explanations as PE, including kernel and I/O
privilege requirements. Classification uses the shared iced-x86 instruction metadata
and [instruction catalog](pe-special-instructions.md).

Findings are collected during the existing control-flow traversal, without a second
decode pass. Counts represent decoded instruction sites, not execution frequency.
Unvisited code can contain additional instructions. Invalid or truncated decodes
retain earlier findings and appear in the analysis notes.

Each instruction includes at most three exact virtual-address examples. Addresses
retain all 64 bits and are displayed as hexadecimal text. They are not PE RVAs and
do not open the PE disassembly explorer. AArch64 analysis is unchanged.
