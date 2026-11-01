/* nika-fuzz dwrite-x86 adapter: modern UCRT stubs.
 *
 * This newer dwrite.dll dynamically imports the ucrt (api-ms-win-crt-*) surface. mpengine, which
 * loadlibrary was built for, static-linked its CRT, so loadlibrary does not provide these. Each
 * stub forwards to glibc, or carries a minimal implementation. The CRT is cdecl, not WINAPI.
 *
 * WCHAR is 2 bytes here (loadlibrary builds with -fshort-wchar), so the wide-string stubs run over
 * uint16_t and must not forward to glibc's 4-byte wchar_t functions.
 *
 * Scope: enough of the CRT for DllMain and the font-parse front door. The _libm_sse2_*_precise
 * routines use MSVC's internal xmm calling convention; they are stubbed to 0.0 and are not on the
 * parse path to CreateFontFace. Revisit if a harness reaches them.
 */
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <search.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "util.h"
#include "winexports.h"

typedef uint16_t w16;
typedef int errno_t;

/* ---- allocator and misc CRT, forwarded to glibc (cdecl) ---- */
static void *o_malloc(size_t n) { return malloc(n); }
static void *o_calloc(size_t n, size_t s) { return calloc(n, s); }
static void *o_realloc(void *p, size_t n) { return realloc(p, n); }
static void o_free(void *p) { free(p); }
static void *o_bsearch(const void *k, const void *b, size_t n, size_t s,
                       int (*c)(const void *, const void *)) { return bsearch(k, b, n, s, c); }
static void o_qsort(void *b, size_t n, size_t s,
                    int (*c)(const void *, const void *)) { qsort(b, n, s, c); }
static double o_ceil(double x) { return ceil(x); }
static double o_floor(double x) { return floor(x); }
static float o_roundf(float x) { return roundf(x); }
static double o_strtod(const char *s, char **e) { return strtod(s, e); }
static int o_rand(void) { return rand(); }
static char *o_strerror(int e) { return strerror(e); }
static int o_isalnum(int c) { return isalnum(c); }
static int o_isspace(int c) { return isspace(c); }
static int o_iswalpha(unsigned c) { return (c < 128) ? isalpha((int)c) : 1; }
static int *o_errno(void) { return &errno; }
static size_t c_strnlen(const char *s, size_t m) { return strnlen(s, m); }

/* ---- wide string (2-byte WCHAR), hand-written ---- */
static w16 *o_wcschr(const w16 *s, w16 c)
{
    for (; *s; s++)
        if (*s == c)
            return (w16 *)s;
    return (c == 0) ? (w16 *)s : NULL;
}
static w16 *o_wcsrchr(const w16 *s, w16 c)
{
    const w16 *last = NULL;
    for (;; s++) {
        if (*s == c)
            last = s;
        if (*s == 0)
            break;
    }
    return (w16 *)last;
}
static size_t o_wcsnlen(const w16 *s, size_t m)
{
    size_t n = 0;
    while (n < m && s[n])
        n++;
    return n;
}
static int o_wcsicmp(const w16 *a, const w16 *b)
{
    for (; *a && *b; a++, b++) {
        w16 ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca += 32;
        if (cb >= 'A' && cb <= 'Z')
            cb += 32;
        if (ca != cb)
            return (int)ca - (int)cb;
    }
    return (int)*a - (int)*b;
}
static errno_t o_itow_s(int value, w16 *buf, size_t n, int radix)
{
    char tmp[34];
    if (buf == NULL || n == 0)
        return EINVAL;
    snprintf(tmp, sizeof(tmp), (radix == 16) ? "%x" : "%d", value);
    size_t i = 0;
    for (; tmp[i] && i + 1 < n; i++)
        buf[i] = (w16)(unsigned char)tmp[i];
    buf[i] = 0;
    return 0;
}
static errno_t o_ultow_s(unsigned long value, w16 *buf, size_t n, int radix)
{
    char tmp[34];
    if (buf == NULL || n == 0)
        return EINVAL;
    snprintf(tmp, sizeof(tmp), (radix == 16) ? "%lx" : "%lu", value);
    size_t i = 0;
    for (; tmp[i] && i + 1 < n; i++)
        buf[i] = (w16)(unsigned char)tmp[i];
    buf[i] = 0;
    return 0;
}

/* ---- secure narrow string ---- */
static errno_t o_strcpy_s(char *dst, size_t n, const char *src)
{
    if (dst == NULL || src == NULL || n == 0)
        return EINVAL;
    size_t len = strlen(src);
    if (len + 1 > n) {
        dst[0] = 0;
        return ERANGE;
    }
    memcpy(dst, src, len + 1);
    return 0;
}
static errno_t o_strcat_s(char *dst, size_t n, const char *src)
{
    if (dst == NULL || src == NULL || n == 0)
        return EINVAL;
    size_t dl = strnlen(dst, n);
    if (dl == n)
        return EINVAL;
    return o_strcpy_s(dst + dl, n - dl, src);
}
static errno_t o_strncpy_s(char *dst, size_t n, const char *src, size_t count)
{
    if (dst == NULL || n == 0)
        return EINVAL;
    if (src == NULL) {
        dst[0] = 0;
        return (count == 0) ? 0 : EINVAL;
    }
    size_t len = strnlen(src, count);
    if (len + 1 > n) {
        dst[0] = 0;
        return ERANGE;
    }
    memcpy(dst, src, len);
    dst[len] = 0;
    return 0;
}

/* ---- CRT init / exit ---- */
typedef void (*PVFV)(void);
typedef int (*PVFI)(void);
static void o_initterm(PVFV *first, PVFV *last)
{
    for (PVFV *p = first; p < last; p++)
        if (*p)
            (*p)();
}
static int o_initterm_e(PVFI *first, PVFI *last)
{
    for (PVFI *p = first; p < last; p++)
        if (*p) {
            int r = (*p)();
            if (r)
                return r;
        }
    return 0;
}
static void o_cexit(void) {}
static int o_crt_atexit(void (*f)(void)) { (void)f; return 0; }
static int o_configure_narrow_argv(int mode) { (void)mode; return 0; }
static int o_initialize_narrow_environment(void) { return 0; }
static int o_initialize_onexit_table(void *table) { (void)table; return 0; }
static int o_register_onexit_function(void *table, void *func) { (void)table; (void)func; return 0; }
static int o_execute_onexit_table(void *table) { (void)table; return 0; }
static int o_callnewh(size_t size) { (void)size; return 0; }
static void o_purecall(void) { abort(); }
static void o_invalid_parameter_noinfo(void) {}
static int o_seh_filter_dll(unsigned code, void *ep) { (void)code; (void)ep; return 0; }
static void o_terminate(void) { abort(); }
static void o_invoke_watson(const w16 *a, const w16 *b, const w16 *c, unsigned d, uintptr_t e)
{
    (void)a; (void)b; (void)c; (void)d; (void)e;
    abort();
}

/* ---- stdio (minimal; not expected on the parse path) ---- */
static int o_stdio_common_vsscanf(uint64_t opt, const char *buf, size_t n, const char *fmt,
                                  void *loc, va_list ap)
{
    (void)opt; (void)buf; (void)n; (void)fmt; (void)loc; (void)ap;
    return -1;
}
static int o_stdio_common_vswprintf(uint64_t opt, w16 *buf, size_t n, const w16 *fmt,
                                    void *loc, va_list ap)
{
    (void)opt; (void)fmt; (void)loc; (void)ap;
    if (buf && n)
        buf[0] = 0;
    return 0;
}

/* ---- libm precise (MSVC xmm convention; stubbed, not on the parse path) ---- */
static double o_libm_cos(double x) { (void)x; return 0.0; }
static double o_libm_exp(double x) { (void)x; return 0.0; }
static double o_libm_log10(double x) { (void)x; return 0.0; }
static double o_libm_log(double x) { (void)x; return 0.0; }
static double o_libm_pow(double x, double y) { (void)x; (void)y; return 0.0; }
static double o_libm_sin(double x) { (void)x; return 0.0; }
static double o_libm_sqrt(double x) { (void)x; return 0.0; }
static double o_libm_tan(double x) { (void)x; return 0.0; }

/* ---- ntdll (thread/stack queries; benign zeros) ---- */
static NTSTATUS o_NtQueryInformationThread(HANDLE t, int c, void *i, ULONG l, ULONG *r)
{
    (void)t; (void)c; (void)l;
    if (i && l)
        memset(i, 0, l);
    if (r)
        *r = l;
    return 0;
}
static NTSTATUS o_NtSetInformationThread(HANDLE t, int c, void *i, ULONG l)
{
    (void)t; (void)c; (void)i; (void)l;
    return 0;
}
static USHORT o_RtlCaptureStackBackTrace(ULONG skip, ULONG n, void **frames, ULONG *hash)
{
    (void)skip; (void)n; (void)frames;
    if (hash)
        *hash = 0;
    return 0;
}

/* ---- wave 2: more CRT ---- */
static long o_wcstol(const w16 *s, w16 **end, int base)
{
    const w16 *p = s;
    while (*p == ' ' || *p == '\t')
        p++;
    int neg = 0;
    if (*p == '+' || *p == '-') {
        neg = (*p == '-');
        p++;
    }
    if ((base == 0 || base == 16) && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        base = 16;
    } else if (base == 0) {
        base = (p[0] == '0') ? 8 : 10;
    }
    long acc = 0;
    for (; *p; p++) {
        int d;
        if (*p >= '0' && *p <= '9')
            d = *p - '0';
        else if (*p >= 'a' && *p <= 'z')
            d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'Z')
            d = *p - 'A' + 10;
        else
            break;
        if (d >= base)
            break;
        acc = acc * base + d;
    }
    if (end)
        *end = (w16 *)p;
    return neg ? -acc : acc;
}
static void *o_acrt_iob_func(unsigned i) { return (i == 0) ? stdin : (i == 1) ? stdout : stderr; }
static int o_stdio_common_vfprintf(uint64_t opt, FILE *f, const char *fmt, void *loc, va_list ap)
{ (void)opt; (void)loc; return vfprintf(f, fmt, ap); }
static int o_stdio_common_vsprintf(uint64_t opt, char *buf, size_t n, const char *fmt, void *loc, va_list ap)
{ (void)opt; (void)loc; if (buf == NULL || n == 0) return 0; return vsnprintf(buf, n, fmt, ap); }
static int o_stdio_common_vsprintf_s(uint64_t opt, char *buf, size_t n, const char *fmt, void *loc, va_list ap)
{ (void)opt; (void)loc; if (buf == NULL || n == 0) return 0; return vsnprintf(buf, n, fmt, ap); }
static int o_stdio_common_vsnprintf_s(uint64_t opt, char *buf, size_t n, size_t count, const char *fmt,
                                      void *loc, va_list ap)
{ (void)opt; (void)loc; if (buf == NULL || n == 0) return 0;
  size_t lim = (count + 1 < n) ? count + 1 : n; return vsnprintf(buf, lim, fmt, ap); }
static void o_std_exception_copy(const void *from, void *to) { (void)from; (void)to; }
static void o_std_exception_destroy(void *p) { (void)p; }
static void o_std_type_info_destroy_list(void *p) { (void)p; }
static double o_CIatan2(void) { return 0.0; }

DECLARE_CRT_EXPORT("_o_malloc", o_malloc);
DECLARE_CRT_EXPORT("_o_calloc", o_calloc);
DECLARE_CRT_EXPORT("_o_realloc", o_realloc);
DECLARE_CRT_EXPORT("_o_free", o_free);
DECLARE_CRT_EXPORT("_o_bsearch", o_bsearch);
DECLARE_CRT_EXPORT("_o_qsort", o_qsort);
DECLARE_CRT_EXPORT("_o_ceil", o_ceil);
DECLARE_CRT_EXPORT("_o_floor", o_floor);
DECLARE_CRT_EXPORT("_o_roundf", o_roundf);
DECLARE_CRT_EXPORT("_o_strtod", o_strtod);
DECLARE_CRT_EXPORT("_o_rand", o_rand);
DECLARE_CRT_EXPORT("_o_strerror", o_strerror);
DECLARE_CRT_EXPORT("_o_isalnum", o_isalnum);
DECLARE_CRT_EXPORT("_o_isspace", o_isspace);
DECLARE_CRT_EXPORT("_o_iswalpha", o_iswalpha);
DECLARE_CRT_EXPORT("_o__errno", o_errno);
DECLARE_CRT_EXPORT("strnlen", c_strnlen);
DECLARE_CRT_EXPORT("wcschr", o_wcschr);
DECLARE_CRT_EXPORT("wcsrchr", o_wcsrchr);
DECLARE_CRT_EXPORT("wcsnlen", o_wcsnlen);
DECLARE_CRT_EXPORT("_o__wcsicmp", o_wcsicmp);
DECLARE_CRT_EXPORT("_o__itow_s", o_itow_s);
DECLARE_CRT_EXPORT("_o__ultow_s", o_ultow_s);
DECLARE_CRT_EXPORT("_o_strcpy_s", o_strcpy_s);
DECLARE_CRT_EXPORT("_o_strcat_s", o_strcat_s);
DECLARE_CRT_EXPORT("_o_strncpy_s", o_strncpy_s);
DECLARE_CRT_EXPORT("_initterm", o_initterm);
DECLARE_CRT_EXPORT("_initterm_e", o_initterm_e);
DECLARE_CRT_EXPORT("_o__cexit", o_cexit);
DECLARE_CRT_EXPORT("_o__crt_atexit", o_crt_atexit);
DECLARE_CRT_EXPORT("_o__configure_narrow_argv", o_configure_narrow_argv);
DECLARE_CRT_EXPORT("_o__initialize_narrow_environment", o_initialize_narrow_environment);
DECLARE_CRT_EXPORT("_o__initialize_onexit_table", o_initialize_onexit_table);
DECLARE_CRT_EXPORT("_o__register_onexit_function", o_register_onexit_function);
DECLARE_CRT_EXPORT("_o__execute_onexit_table", o_execute_onexit_table);
DECLARE_CRT_EXPORT("_o__callnewh", o_callnewh);
DECLARE_CRT_EXPORT("_o__purecall", o_purecall);
DECLARE_CRT_EXPORT("_o__invalid_parameter_noinfo", o_invalid_parameter_noinfo);
DECLARE_CRT_EXPORT("_o__seh_filter_dll", o_seh_filter_dll);
DECLARE_CRT_EXPORT("_o_terminate", o_terminate);
DECLARE_CRT_EXPORT("_invoke_watson", o_invoke_watson);
DECLARE_CRT_EXPORT("_o___stdio_common_vsscanf", o_stdio_common_vsscanf);
DECLARE_CRT_EXPORT("_o___stdio_common_vswprintf", o_stdio_common_vswprintf);
DECLARE_CRT_EXPORT("_o__libm_sse2_cos_precise", o_libm_cos);
DECLARE_CRT_EXPORT("_o__libm_sse2_exp_precise", o_libm_exp);
DECLARE_CRT_EXPORT("_o__libm_sse2_log10_precise", o_libm_log10);
DECLARE_CRT_EXPORT("_o__libm_sse2_log_precise", o_libm_log);
DECLARE_CRT_EXPORT("_o__libm_sse2_pow_precise", o_libm_pow);
DECLARE_CRT_EXPORT("_o__libm_sse2_sin_precise", o_libm_sin);
DECLARE_CRT_EXPORT("_o__libm_sse2_sqrt_precise", o_libm_sqrt);
DECLARE_CRT_EXPORT("_o__libm_sse2_tan_precise", o_libm_tan);
DECLARE_CRT_EXPORT("NtQueryInformationThread", o_NtQueryInformationThread);
DECLARE_CRT_EXPORT("NtSetInformationThread", o_NtSetInformationThread);
DECLARE_CRT_EXPORT("RtlCaptureStackBackTrace", o_RtlCaptureStackBackTrace);
DECLARE_CRT_EXPORT("_o_wcstol", o_wcstol);
DECLARE_CRT_EXPORT("_o___acrt_iob_func", o_acrt_iob_func);
DECLARE_CRT_EXPORT("_o___stdio_common_vfprintf", o_stdio_common_vfprintf);
DECLARE_CRT_EXPORT("_o___stdio_common_vsprintf", o_stdio_common_vsprintf);
DECLARE_CRT_EXPORT("_o___stdio_common_vsprintf_s", o_stdio_common_vsprintf_s);
DECLARE_CRT_EXPORT("_o___stdio_common_vsnprintf_s", o_stdio_common_vsnprintf_s);
DECLARE_CRT_EXPORT("_o___std_exception_copy", o_std_exception_copy);
DECLARE_CRT_EXPORT("_o___std_exception_destroy", o_std_exception_destroy);
DECLARE_CRT_EXPORT("_o___std_type_info_destroy_list", o_std_type_info_destroy_list);
DECLARE_CRT_EXPORT("_o__CIatan2", o_CIatan2);
