#ifndef IG5_NATIVE_DECOMPILER_H
#define IG5_NATIVE_DECOMPILER_H
#include <stddef.h>
#include <stdint.h>
#if defined(_WIN32) && defined(IG5_DECOMPILER_BUILD)
#define IG5_DECOMPILER_API __declspec(dllexport)
#elif defined(_WIN32)
#define IG5_DECOMPILER_API __declspec(dllimport)
#else
#define IG5_DECOMPILER_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif

enum ig5_decompiler_region_flags {
    IG5_DEC_READONLY = 1,
    IG5_DEC_EXECUTABLE = 2,
    /* A missing data tail represents explicitly mapped BSS, not a hole. */
    IG5_DEC_ZERO_FILL_TAIL = 4
};
typedef struct ig5_decompiler_region {
    uint64_t start;
    uint64_t size;
    const uint8_t *data;
    size_t data_length;
    uint32_t flags;
} ig5_decompiler_region;

/* A spec directory contains .ldefs, .sla, .pspec and .cspec files. The first
 * successful call fixes this directory for the process lifetime. On Windows,
 * prefer an ASCII relative path under a child process's fixed Unicode CWD.
 * target includes compiler ID, e.g. x86:LE:64:default:windows.
 * Function bounds are [function_begin, function_end); entry is inside them.
 * max_instructions bounds flow decoding, NOT total optimizer time. Calls must
 * run in an owned isolated worker with an external deadline/resource budget.
 * No supplied image byte or original file is modified.
 * Status: 0 complete, 1 output buffer too small, 2 invalid input,
 * 3 native analysis failed/incomplete, 4 resource budget exhausted.
 * required includes the terminating NUL. Allocate a bounded output buffer up
 * front; a capacity query repeats analysis on a later call (no cached result).
 */
IG5_DECOMPILER_API int ig5_decompiler_function(
    const char *spec_directory, const char *target,
    const ig5_decompiler_region *regions, size_t region_count,
    uint64_t entry, uint64_t function_begin, uint64_t function_end,
    uint32_t max_instructions, char *output, size_t capacity, size_t *required);

#ifdef __cplusplus
}
#endif
#endif
