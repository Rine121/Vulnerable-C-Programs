/*
 * got_overwrite.c
 *
 * Demonstrates a write primitive being used to corrupt a Global Offset
 * Table (GOT) entry. Used to test: partial RELRO vs. full RELRO
 * ("-Wl,-z,relro" vs "-Wl,-z,relro,-z,now").
 *
 * The program has an out-of-bounds WRITE via an array index read from
 * input, with no bounds checking. On a non-RELRO or partial-RELRO
 * binary, the GOT is writable at runtime, so a correctly computed
 * offset/value pair can redirect a future call through the GOT
 * (e.g., retarget puts()) to attacker-chosen code such as system().
 * On a full-RELRO binary the GOT page is read-only after startup,
 * so the same write should fail with a segfault instead of hijacking
 * control flow.
 *
 * Adapted/inspired by the vulnerability style in Hardik05's
 * "Damn Vulnerable C Program" (see reference [6]).
 *
 * USAGE:
 *   ./got_overwrite <array_index> <value_as_hex>
 *
 * Example (illustrative only -- real offsets must be found with
 * objdump/readelf against the specific compiled binary):
 *   ./got_overwrite 1234 0x4141414141414141
 *
 * DO NOT deploy or run this against anything other than your own
 * isolated test environment. This file is intentionally vulnerable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A small fixed-size array. The index used to write into it is taken
 * directly from user input with no bounds checking, so a large/negative
 * index lets the caller write to memory far outside this array --
 * including, with the right offset, into the GOT. */
long data[8];

void vulnerable_write(long index, long value) {
    /* Intentionally unsafe: no bounds check on index. */
    data[index] = value;
    printf("Wrote value 0x%lx at index %ld\n", value, index);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <array_index> <value_as_hex>\n", argv[0]);
        return 1;
    }

    long index = strtol(argv[1], NULL, 10);
    long value = strtol(argv[2], NULL, 16);

    vulnerable_write(index, value);

    /* This call is the "payload trigger": if the GOT entry for puts
     * (or a nearby function) was successfully overwritten, this call
     * redirects control flow instead of printing normally. */
    puts("Reached the vulnerable call site normally.");

    return 0;
}
