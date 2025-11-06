/* Copyright 2025 syzkaller project authors. All rights reserved. */
/* Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file. */

/* Defines a basic linkage script for building kernel-like KFuzzTest metadata into a binary. */
PAGE_SIZE = 0x1000;

PHDRS
{
    text PT_LOAD FLAGS(5); /* R, X */
    data PT_LOAD FLAGS(6); /* R, W */
}

SECTIONS
{
    .text : { *(.text) } :text

    .rodata : {
        *(.rodata*)

        . = ALIGN(PAGE_SIZE);
        __kfuzztest_targets_start = .;
        KEEP(*(.kfuzztest_target));
        __kfuzztest_targets_end = .;

        . = ALIGN(PAGE_SIZE);
        __kfuzztest_constraints_start = .;
        KEEP(*(.kfuzztest_constraint));
        __kfuzztest_constraints_end = .;

        . = ALIGN(PAGE_SIZE);
        __kfuzztest_annotations_start = .;
        KEEP(*(.kfuzztest_annotation));
        __kfuzztest_annotations_end = .;

    } :text

    .data : { *(.data) } :data
    .bss : { *(.bss) } :data
}
