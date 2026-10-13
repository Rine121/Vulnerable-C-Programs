/*
 * leak_and_hijack.c
 *
 * Demonstrates why PIE only matters when combined with OS-level ASLR,
 * and why an information leak defeats both. Used to test the
 * PIE x ASLR 2x2 (PIE on/off, ASLR on/off).
 *
 * The program contains:
 *   1) An intentional information-leak bug: it prints the address of
 *      a function pointer it holds (simulating a format-string leak
 *      or similar info-disclosure bug).
 *   2) A classic stack buffer overflow (as in stack_overflow.c) that
 *      can overwrite the saved return address.
 *
 * Expected behavior across configurations:
 *   - Non-PIE, ASLR off/on:  code section loads at the SAME fixed
 *     address every run (ASLR cannot randomize a non-PIE binary's
 *     own code on x86-64), so a hardcoded target address works
 *     without needing the leak at all.
 *   - PIE, ASLR off: PIE binary still loads at the same base every
 *     run because ASLR is disabled, so again a hardcoded address
 *     works -- this demonstrates "PIE alone does nothing."
 *   - PIE, ASLR on: the base address changes every run. A hardcoded
 *     address will fail almost all the time; the attacker must use
 *     the leaked address printed by the program to compute the real
 *     target at runtime. This demonstrates "PIE needs ASLR, and an
 *     info leak defeats both."
 *
 * Adapted/inspired by the vulnerability style in Hardik05's
 * "Damn Vulnerable C Program" (see reference [6]).
 *
 * USAGE:
 *   ./leak_and_hijack <input_file>
 *
 * DO NOT deploy or run this against anything other than your own
 * isolated test environment. This file is intentionally vulnerable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win_function(void) {
    printf("[!] win_function() reached -- control-flow hijack succeeded\n");
}

/* Held here so its address can be "leaked" just like a real info-leak
 * bug might disclose a function pointer, stack address, or similar. */
void (*leaky_pointer)(void) = win_function;

void vulnerable_copy(char *input) {
    char buffer[64];
    strcpy(buffer, input); /* intentionally unsafe */
    printf("Buffer contents: %s\n", buffer);
}

char *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len > 4096) len = 4096;

    char *buf = malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);

    *out_len = len;
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Step 1: simulate the information leak. In a real bug this might
     * be a format-string vulnerability; here it is made explicit so
     * the experiment can toggle "attacker has the leak" on and off
     * by choosing whether to use this printed value. */
    printf("LEAK: win_function address = %p\n", (void *)leaky_pointer);

    /* Step 2: the actual overflow. */
    long len;
    char *input = read_file(argv[1], &len);
    printf("Read %ld bytes from %s\n", len, argv[1]);
    vulnerable_copy(input);

    free(input);
    printf("Function returned normally.\n");
    return 0;
}
