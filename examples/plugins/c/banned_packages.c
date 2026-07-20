/*
 * PledgeRecon WASM Plugin — C Example (Goal 54)
 *
 * This plugin flags dependencies on outdated or banned packages.
 * It demonstrates the PledgeRecon WASM plugin interface using C.
 *
 * Build (with wasi-sdk or clang):
 *   clang --target=wasm32-wasi \
 *     -O2 \
 *     -Wl,--export=check \
 *     -Wl,--export=alloc \
 *     -Wl,--export-memory \
 *     -o banned_packages.wasm \
 *     banned_packages.c
 *
 * Or with wasi-sdk:
 *   /opt/wasi-sdk/bin/clang \
 *     --target=wasm32-wasi \
 *     -O2 \
 *     -Wl,--export=check \
 *     -Wl,--export=alloc \
 *     -o banned_packages.wasm \
 *     banned_packages.c
 *
 * Usage:
 *   pledgerecon scan . --wasm-rules --wasm-rule ./examples/plugins/c/banned_packages.wasm
 */

#include <string.h>
#include <stdlib.h>

/* Simple heap allocator for WASM — bump allocator */
static char heap[65536];
static int heap_offset = 0;

/* Export: alloc(size) -> ptr
 * Allocate `size` bytes in WASM memory for the host to write input into. */
__attribute__((visibility("default")))
int alloc(int size) {
    int ptr = heap_offset;
    heap_offset += size;
    /* Align to 8 bytes */
    heap_offset = (heap_offset + 7) & ~7;
    if (heap_offset >= (int)sizeof(heap)) {
        return 0; /* Out of memory */
    }
    return ptr;
}

/* Export: check(ptr, len) -> result_ptr
 * Check a dependency. `ptr` points to input JSON of length `len`.
 * Returns pointer to output JSON (null-terminated), or 0 if no finding. */
__attribute__((visibility("default")))
int check(int ptr, int len) {
    /* Read input from memory */
    char input[4096];
    if (len >= (int)sizeof(input)) {
        return 0; /* Input too large */
    }
    memcpy(input, (void*)(size_t)ptr, len);
    input[len] = '\0';

    /* Check for banned packages using simple string search */
    const char *output = NULL;

    if (strstr(input, "\"unsafe-pkg\"") != NULL) {
        output = "{\"is_vulnerable\":true,\"severity\":\"critical\","
                 "\"summary\":\"Internal package 'unsafe-pkg' is banned\","
                 "\"description\":\"This package has been flagged by security policy.\","
                 "\"fix_version\":null}";
    } else if (strstr(input, "\"lodash\"") != NULL &&
               strstr(input, "\"4.17.0\"") != NULL) {
        output = "{\"is_vulnerable\":true,\"severity\":\"high\","
                 "\"summary\":\"lodash 4.17.0 has known prototype pollution\","
                 "\"description\":\"Upgrade to lodash 4.17.21 or later to fix CVE-2021-23337.\","
                 "\"fix_version\":\"4.17.21\"}";
    } else if (strstr(input, "\"express\"") != NULL &&
               strstr(input, "\"3.0.0\"") != NULL) {
        output = "{\"is_vulnerable\":true,\"severity\":\"medium\","
                 "\"summary\":\"express 3.x is end-of-life\","
                 "\"description\":\"Express 3.x is no longer maintained and may have unpatched vulnerabilities.\","
                 "\"fix_version\":\"4.0.0\"}";
    }

    if (output == NULL) {
        return 0; /* No finding */
    }

    /* Write output to heap memory */
    int output_len = (int)strlen(output);
    int output_ptr = alloc(output_len + 1);
    if (output_ptr == 0) {
        return 0;
    }
    memcpy((void*)(size_t)output_ptr, output, output_len);
    ((char*)(size_t)output_ptr)[output_len] = '\0'; /* null terminator */

    return output_ptr;
}
