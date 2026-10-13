/*
 * stack_overflow.c
 *
 * Demonstrates a classic stack buffer overflow that overwrites a saved
 * return address. Used to test: stack canaries, NX (non-executable stack),
 * and PIE+ASLR (since a successful return-to-X attack needs a known
 * target address).
 *
 * Adapted/inspired by the vulnerability style in Hardik05's
 * "Damn Vulnerable C Program" (see reference [6]).
 *
 * USAGE:
 *   ./stack_overflow <input_file>
 *
 * The program reads up to 256 bytes from a file into a 64-byte stack
 * buffer with no bounds checking (vulnerable_copy uses strcpy).
 * An input longer than 64 bytes (plus padding) will overwrite the
 * saved return address on the stack.
 *
 * DO NOT deploy or run this against anything other than your own
 * isolated test environment. This file is intentionally vulnerable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A function an attacker should never be able to reach directly. */
void win_function(void) {
    printf("[!] win_function() reached -- control-flow hijack succeeded\n");
}

void vulnerable_copy(char *input) {
    char buffer[64];
    /* Intentionally unsafe: no bounds checking. */
    strcpy(buffer, input);
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

    /* Cap read size; this is just an input-loading limit, not a fix
     * for the vulnerability below. */
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

    long len;
    char *input = read_file(argv[1], &len);

    printf("Read %ld bytes from %s\n", len, argv[1]);
    vulnerable_copy(input);

    free(input);
    printf("Function returned normally.\n");
    return 0;
}
