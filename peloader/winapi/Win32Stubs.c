/* nika-fuzz dwrite-x86 adapter: benign Win32 stubs (WINAPI / stdcall).
 *
 * dwrite.dll imports these from the api-ms-win-core-* umbrella DLLs. loadlibrary does not provide
 * them. Each stub returns a benign value so DllMain and the font-parse path proceed: registry
 * reads report "not found" (dwrite uses defaults), resource/file/thread calls fail softly, debug
 * output is dropped. None are on the memory-safety parse path of the planned harnesses.
 */
#include <stdbool.h>
#include <search.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "util.h"
#include "winexports.h"

#define ERROR_FILE_NOT_FOUND 2
#define ERROR_NO_MORE_ITEMS 259

STATIC void WINAPI st_DebugBreak(void) {}
STATIC void WINAPI st_OutputDebugStringA(const char *s) { (void)s; }
STATIC void WINAPI st_OutputDebugStringW(const void *s) { (void)s; }
STATIC UINT WINAPI st_SetErrorMode(UINT m) { (void)m; return 0; }

STATIC BOOL WINAPI st_FindClose(HANDLE h) { (void)h; return TRUE; }
STATIC BOOL WINAPI st_FindCloseChangeNotification(HANDLE h) { (void)h; return TRUE; }
STATIC HANDLE WINAPI st_FindFirstChangeNotificationW(const void *p, BOOL sub, DWORD f)
{ (void)p; (void)sub; (void)f; return INVALID_HANDLE_VALUE; }
STATIC BOOL WINAPI st_FindNextChangeNotification(HANDLE h) { (void)h; return FALSE; }
STATIC BOOL WINAPI st_GetFileInformationByHandle(HANDLE h, void *info) { (void)h; (void)info; return FALSE; }
STATIC BOOL WINAPI st_SetFileTime(HANDLE h, const void *a, const void *b, const void *c)
{ (void)h; (void)a; (void)b; (void)c; return TRUE; }

STATIC BOOL WINAPI st_DisableThreadLibraryCalls(HANDLE m) { (void)m; return TRUE; }
STATIC void *WINAPI st_FindResourceExW(HANDLE m, const void *t, const void *n, uint16_t lang)
{ (void)m; (void)t; (void)n; (void)lang; return NULL; }
STATIC void *WINAPI st_LoadResource(HANDLE m, void *r) { (void)m; (void)r; return NULL; }
STATIC void *WINAPI st_LockResource(void *r) { (void)r; return NULL; }
STATIC DWORD WINAPI st_SizeofResource(HANDLE m, void *r) { (void)m; (void)r; return 0; }
STATIC void WINAPI st_FreeLibraryAndExitThread(HANDLE m, DWORD code) { (void)m; (void)code; }

STATIC DWORD WINAPI st_FormatMessageW(DWORD f, const void *src, DWORD id, DWORD lang,
                                      void *buf, DWORD sz, void *args)
{ (void)f; (void)src; (void)id; (void)lang; (void)buf; (void)sz; (void)args; return 0; }

STATIC HANDLE WINAPI st_CreateThread(void *sa, SIZE_T stk, void *start, void *param,
                                     DWORD flags, DWORD *tid)
{ (void)sa; (void)stk; (void)start; (void)param; (void)flags; if (tid) *tid = 0; return NULL; }
STATIC BOOL WINAPI st_TerminateProcess(HANDLE h, UINT code) { (void)h; (void)code; return TRUE; }

STATIC LONG WINAPI st_RegEnumKeyExW(HANDLE k, DWORD i, void *name, DWORD *nlen, DWORD *res,
                                    void *cls, DWORD *clen, void *ft)
{ (void)k; (void)i; (void)name; (void)nlen; (void)res; (void)cls; (void)clen; (void)ft;
  return ERROR_NO_MORE_ITEMS; }
STATIC LONG WINAPI st_RegEnumValueW(HANDLE k, DWORD i, void *name, DWORD *nlen, DWORD *res,
                                    DWORD *type, void *data, DWORD *dlen)
{ (void)k; (void)i; (void)name; (void)nlen; (void)res; (void)type; (void)data; (void)dlen;
  return ERROR_NO_MORE_ITEMS; }
STATIC LONG WINAPI st_RegGetValueW(HANDLE k, const void *sub, const void *val, DWORD flags,
                                   DWORD *type, void *data, DWORD *dlen)
{ (void)k; (void)sub; (void)val; (void)flags; if (type) *type = 0; if (dlen) *dlen = 0;
  return ERROR_FILE_NOT_FOUND; }
STATIC LONG WINAPI st_RegNotifyChangeKeyValue(HANDLE k, BOOL sub, DWORD filter, HANDLE ev, BOOL async)
{ (void)k; (void)sub; (void)filter; (void)ev; (void)async; return 0; }

STATIC DWORD WINAPI st_WaitForMultipleObjectsEx(DWORD n, const void *h, BOOL all, DWORD ms, BOOL alert)
{ (void)n; (void)h; (void)all; (void)ms; (void)alert; return 0; }

/* Security: dwrite's ComputeIsTheAllPackagesSidDefined checks an AppContainer SID. Report the SID
 * as not creatable so dwrite takes the default (non-AppContainer) path. */
STATIC BOOL WINAPI st_CreateWellKnownSid(int type, void *domain, void *sid, DWORD *cb)
{ (void)type; (void)domain; (void)sid; (void)cb; return FALSE; }
STATIC BOOL WINAPI st_RevertToSelf(void) { return TRUE; }
STATIC BOOL WINAPI st_ImpersonateLoggedOnUser(HANDLE tok) { (void)tok; return TRUE; }

/* ETW (tracelogging): dwrite emits events everywhere. Drop them. */
STATIC ULONG WINAPI st_EventSetInformation(uint64_t reg, int cls, void *info, ULONG len)
{ (void)reg; (void)cls; (void)info; (void)len; return 0; }
STATIC ULONG WINAPI st_EventWriteTransfer(uint64_t reg, const void *desc, const void *act,
                                          const void *rel, ULONG n, void *data)
{ (void)reg; (void)desc; (void)act; (void)rel; (void)n; (void)data; return 0; }

/* COM task allocator, on the parse path. */
STATIC void *WINAPI st_CoTaskMemAlloc(SIZE_T n) { return malloc(n); }
STATIC void WINAPI st_CoTaskMemFree(void *p) { free(p); }

/* Minimal locale string compare over 2-byte WCHAR. 1=less, 2=equal, 3=greater (CSTR_*). */
STATIC int WINAPI st_CompareStringW(DWORD lcid, DWORD flags, const uint16_t *a, int la,
                                    const uint16_t *b, int lb)
{
    (void)lcid; (void)flags;
    int i = 0;
    for (;; i++) {
        bool ea = (la >= 0) ? (i >= la) : (a[i] == 0);
        bool eb = (lb >= 0) ? (i >= lb) : (b[i] == 0);
        if (ea && eb)
            return 2;
        if (ea)
            return 1;
        if (eb)
            return 3;
        if (a[i] != b[i])
            return (a[i] < b[i]) ? 1 : 3;
    }
}

/* Named sync objects and file mappings: benign handles / soft failure. */
STATIC HANDLE WINAPI st_CreateMutexExW(void *sa, const void *name, DWORD flags, DWORD access)
{ (void)sa; (void)name; (void)flags; (void)access; return (HANDLE)'MUTX'; }
STATIC HANDLE WINAPI st_CreateSemaphoreExW(void *sa, LONG init, LONG max, const void *name,
                                           DWORD flags, DWORD access)
{ (void)sa; (void)init; (void)max; (void)name; (void)flags; (void)access; return (HANDLE)'SEMA'; }
STATIC HANDLE WINAPI st_CreateFileMappingW(HANDLE f, void *sa, DWORD protect, DWORD hi, DWORD lo,
                                           const void *name)
{ (void)f; (void)sa; (void)protect; (void)hi; (void)lo; (void)name; return NULL; }

DECLARE_CRT_EXPORT("DebugBreak", st_DebugBreak);
DECLARE_CRT_EXPORT("OutputDebugStringA", st_OutputDebugStringA);
DECLARE_CRT_EXPORT("OutputDebugStringW", st_OutputDebugStringW);
DECLARE_CRT_EXPORT("SetErrorMode", st_SetErrorMode);
DECLARE_CRT_EXPORT("FindClose", st_FindClose);
DECLARE_CRT_EXPORT("FindCloseChangeNotification", st_FindCloseChangeNotification);
DECLARE_CRT_EXPORT("FindFirstChangeNotificationW", st_FindFirstChangeNotificationW);
DECLARE_CRT_EXPORT("FindNextChangeNotification", st_FindNextChangeNotification);
DECLARE_CRT_EXPORT("GetFileInformationByHandle", st_GetFileInformationByHandle);
DECLARE_CRT_EXPORT("SetFileTime", st_SetFileTime);
DECLARE_CRT_EXPORT("DisableThreadLibraryCalls", st_DisableThreadLibraryCalls);
DECLARE_CRT_EXPORT("FindResourceExW", st_FindResourceExW);
DECLARE_CRT_EXPORT("LoadResource", st_LoadResource);
DECLARE_CRT_EXPORT("LockResource", st_LockResource);
DECLARE_CRT_EXPORT("SizeofResource", st_SizeofResource);
DECLARE_CRT_EXPORT("FreeLibraryAndExitThread", st_FreeLibraryAndExitThread);
DECLARE_CRT_EXPORT("FormatMessageW", st_FormatMessageW);
DECLARE_CRT_EXPORT("CreateThread", st_CreateThread);
DECLARE_CRT_EXPORT("TerminateProcess", st_TerminateProcess);
DECLARE_CRT_EXPORT("RegEnumKeyExW", st_RegEnumKeyExW);
DECLARE_CRT_EXPORT("RegEnumValueW", st_RegEnumValueW);
DECLARE_CRT_EXPORT("RegGetValueW", st_RegGetValueW);
DECLARE_CRT_EXPORT("RegNotifyChangeKeyValue", st_RegNotifyChangeKeyValue);
DECLARE_CRT_EXPORT("WaitForMultipleObjectsEx", st_WaitForMultipleObjectsEx);
DECLARE_CRT_EXPORT("CreateWellKnownSid", st_CreateWellKnownSid);
DECLARE_CRT_EXPORT("RevertToSelf", st_RevertToSelf);
DECLARE_CRT_EXPORT("ImpersonateLoggedOnUser", st_ImpersonateLoggedOnUser);
DECLARE_CRT_EXPORT("EventSetInformation", st_EventSetInformation);
DECLARE_CRT_EXPORT("EventWriteTransfer", st_EventWriteTransfer);
DECLARE_CRT_EXPORT("CoTaskMemAlloc", st_CoTaskMemAlloc);
DECLARE_CRT_EXPORT("CoTaskMemFree", st_CoTaskMemFree);
DECLARE_CRT_EXPORT("CompareStringW", st_CompareStringW);
DECLARE_CRT_EXPORT("CreateMutexExW", st_CreateMutexExW);
DECLARE_CRT_EXPORT("CreateSemaphoreExW", st_CreateSemaphoreExW);
DECLARE_CRT_EXPORT("CreateFileMappingW", st_CreateFileMappingW);
