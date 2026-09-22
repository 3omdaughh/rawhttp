/*
 * Minimal non-libFuzzer driver so the fuzz targets can be built with plain
 * gcc + ASan/UBSan and replayed over a corpus (or crash reproducers) without
 * clang. Each file named on argv is fed once to LLVMFuzzerTestOneInput; with
 * no args it reads a single input from stdin.
 *
 * `make fuzz` builds the real libFuzzer binaries instead (clang), which link
 * their own main and must NOT also pull this one in.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 1; }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return 1; }

    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        /* stdin mode */
        uint8_t stackbuf[65536];
        size_t n = fread(stackbuf, 1, sizeof(stackbuf), stdin);
        LLVMFuzzerTestOneInput(stackbuf, n);
        return 0;
    }

    int rc = 0;
    for (int i = 1; i < argc; i++)
        rc |= run_file(argv[i]);

    fprintf(stderr, "[replay] %d input(s) processed\n", argc - 1);
    return rc;
}
