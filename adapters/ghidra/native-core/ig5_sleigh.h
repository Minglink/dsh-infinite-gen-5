#ifndef IG5_SLEIGH_H
#define IG5_SLEIGH_H
#include <stddef.h>
#include <stdint.h>
#if defined(IG5_SLEIGH_STATIC)
#define IG5_SLEIGH_API
#elif defined(_WIN32) && defined(IG5_SLEIGH_BUILD)
#define IG5_SLEIGH_API __declspec(dllexport)
#elif defined(_WIN32)
#define IG5_SLEIGH_API __declspec(dllimport)
#else
#define IG5_SLEIGH_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct ig5_sleigh_context { const char *name; uint32_t value; } ig5_sleigh_context;
/* Decode bounded bytes using a caller-owned compiled .sla buffer. No filesystem,
 * Java, Python, executable loader or network dependencies. required includes NUL.
 * Returns 0 success, 1 output buffer too small, 2 invalid argument, 3 decode error.
 * JSON reports partial decode errors; no exceptions cross the C ABI.
 * Serialize calls: upstream global XML identifiers are initialized once. */
IG5_SLEIGH_API int ig5_sleigh_decode(
    const uint8_t *sla, size_t sla_size, const uint8_t *code, size_t code_size,
    uint64_t base, const ig5_sleigh_context *context, size_t context_count,
    size_t max_instructions, char *output, size_t output_capacity, size_t *required);
#ifdef __cplusplus
}
#endif
#endif
