#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define MAX_DEFAULTCHAR 2
#define MAX_LEADBYTES 12

typedef struct _cpinfo {
  UINT MaxCharSize;
  BYTE DefaultChar[MAX_DEFAULTCHAR];
  BYTE LeadByte[MAX_LEADBYTES];
} CPINFO, *LPCPINFO;

STATIC UINT GetACP(void)
{
    DebugLog("");

    return 65001;   // UTF-8
}

STATIC WINAPI BOOL IsValidCodePage(UINT CodePage)
{
    DebugLog("%u", CodePage);

    return TRUE;
}

STATIC WINAPI BOOL GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)
{
    DebugLog("%u, %p", CodePage, lpCPInfo);

    memset(lpCPInfo, 0, sizeof *lpCPInfo);

    lpCPInfo->MaxCharSize       = 1;
    lpCPInfo->DefaultChar[0]    = '?';

    return TRUE;
}

STATIC DWORD WINAPI LocaleNameToLCID(PVOID lpName, DWORD dwFlags)
{
    DebugLog("%p, %#x", lpName, dwFlags);
    return 0x0409;
}

STATIC int WINAPI LCIDToLocaleName(DWORD Locale, PUSHORT lpName, int cchName, DWORD dwFlags)
{
    static const WCHAR DefaultLocale[] = L"en-US";
    int Required = sizeof DefaultLocale / sizeof DefaultLocale[0];

    DebugLog("%#x, %p, %d, %#x", Locale, lpName, cchName, dwFlags);

    if (lpName == NULL || cchName == 0) {
        return Required;
    }

    if (cchName < Required) {
        return 0;
    }

    memcpy(lpName, DefaultLocale, sizeof DefaultLocale);
    return Required;
}

STATIC int WINAPI GetUserDefaultLocaleName(PUSHORT lpLocaleName, int cchLocaleName)
{
    DebugLog("%p, %d", lpLocaleName, cchLocaleName);
    return LCIDToLocaleName(0x0409, lpLocaleName, cchLocaleName, 0);
}

STATIC BOOL WINAPI IsValidLocaleName(PUSHORT lpLocaleName)
{
    DebugLog("%p", lpLocaleName);
    return TRUE;
}

STATIC BOOL WINAPI IsValidLocale(DWORD Locale, DWORD dwFlags)
{
    DebugLog("%#x, %#x", Locale, dwFlags);
    return TRUE;
}

typedef BOOL (WINAPI *LOCALE_ENUMPROCEX)(PUSHORT lpLocaleString, DWORD dwFlags, PVOID lParam);

STATIC BOOL WINAPI EnumSystemLocalesEx(LOCALE_ENUMPROCEX lpLocaleEnumProcEx, DWORD dwFlags, PVOID lParam, PVOID lpReserved)
{
    WCHAR DefaultLocale[] = L"en-US";

    DebugLog("%p, %#x, %p, %p", lpLocaleEnumProcEx, dwFlags, lParam, lpReserved);

    if (lpLocaleEnumProcEx != NULL) {
        lpLocaleEnumProcEx(DefaultLocale, dwFlags, lParam);
    }

    return TRUE;
}

#define LCMAP_LOWERCASE 0x00000100
#define LCMAP_UPPERCASE 0x00000200

STATIC WINAPI int LCMapStringA(DWORD Locale, DWORD dwMapFlags, PCHAR lpSrcStr, int cchSrc, PCHAR lpDestStr, int cchDest)
{
    DebugLog("%u, %#x, %p, %d, %p, %d", Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);

    if (cchSrc < 0) {
        cchSrc = strlen(lpSrcStr) + 1;
    }

    if (lpDestStr == NULL || cchDest == 0) {
        return cchSrc;
    }

    int Count = cchDest < cchSrc ? cchDest : cchSrc;
    for (int i = 0; i < Count; i++) {
        unsigned char Ch = lpSrcStr[i];
        if (dwMapFlags & LCMAP_UPPERCASE) {
            Ch = toupper(Ch);
        } else if (dwMapFlags & LCMAP_LOWERCASE) {
            Ch = tolower(Ch);
        }
        lpDestStr[i] = Ch;
    }

    return Count;
}

#define LOCALE_NAME_USER_DEFAULT NULL
#define NORM_IGNORENONSPACE 1
STATIC WINAPI int LCMapStringW(DWORD Locale, DWORD dwMapFlags, PUSHORT lpSrcStr, int cchSrc, PUSHORT lpDestStr, int cchDest)
{
    DebugLog("%u, %#x, %p, %d, %p, %d", Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);

    if (cchSrc < 0) {
        cchSrc = 0;
        while (lpSrcStr[cchSrc++] != 0) {
        }
    }

    if (lpDestStr == NULL || cchDest == 0) {
        return cchSrc;
    }

    int Count = cchDest < cchSrc ? cchDest : cchSrc;
    for (int i = 0; i < Count; i++) {
        USHORT Ch = lpSrcStr[i];
        if ((dwMapFlags & LCMAP_UPPERCASE) && Ch < 0x80) {
            Ch = toupper(Ch);
        } else if ((dwMapFlags & LCMAP_LOWERCASE) && Ch < 0x80) {
            Ch = tolower(Ch);
        }
        lpDestStr[i] = Ch;
    }

    return Count;
}

STATIC WINAPI int LCMapStringEx(PVOID lpLocaleName, DWORD dwMapFlags, PVOID lpSrcStr, int cchSrc, PVOID lpDestStr, int cchDest, PVOID lpVersionInformation, PVOID lpReserved, PVOID sortHandle)
{
    DebugLog("%p, %#x, %p, %d, %p, %d, %p, %p, %p", lpLocaleName, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, lpVersionInformation, lpReserved, sortHandle);

    assert(lpLocaleName == LOCALE_NAME_USER_DEFAULT);

    if (lpDestStr == NULL) {
        return cchSrc;
    }

    memcpy(lpDestStr, lpSrcStr, cchDest > cchSrc ? cchSrc : cchDest);

    return cchDest > cchSrc ? cchSrc : cchDest;
}

STATIC WINAPI int GetLocaleInfoEx(LPCWSTR lpLocaleName, DWORD LCType, LPWSTR lpLCData, int cchData)
{
    DebugLog("%S, %d, %S, %d", lpLocaleName, LCType, lpLCData, cchData);
    return 0;
}

STATIC int WINAPI CompareStringEx(PVOID lpLocaleName,
                                  DWORD dwCmpFlags,
                                  PUSHORT lpString1,
                                  int cchCount1,
                                  PUSHORT lpString2,
                                  int cchCount2,
                                  PVOID lpVersionInformation,
                                  PVOID lpReserved,
                                  PVOID lParam)
{
    int Result;

    DebugLog("%p, %#x, %p, %d, %p, %d, %p, %p, %p",
             lpLocaleName,
             dwCmpFlags,
             lpString1,
             cchCount1,
             lpString2,
             cchCount2,
             lpVersionInformation,
             lpReserved,
             lParam);

    if (cchCount1 < 0) {
        cchCount1 = 0;
        while (lpString1[cchCount1] != 0) {
            cchCount1++;
        }
    }

    if (cchCount2 < 0) {
        cchCount2 = 0;
        while (lpString2[cchCount2] != 0) {
            cchCount2++;
        }
    }

    int Count = cchCount1 < cchCount2 ? cchCount1 : cchCount2;
    Result = memcmp(lpString1, lpString2, Count * sizeof lpString1[0]);

    if (Result < 0 || (Result == 0 && cchCount1 < cchCount2)) {
        return 1;
    }

    if (Result == 0 && cchCount1 == cchCount2) {
        return 2;
    }

    return 3;
}

STATIC int WINAPI GetDateFormatEx(PVOID lpLocaleName,
                                  DWORD dwFlags,
                                  PVOID lpDate,
                                  PUSHORT lpFormat,
                                  PUSHORT lpDateStr,
                                  int cchDate,
                                  PVOID lpCalendar)
{
    static const WCHAR DefaultDate[] = L"01/01/1970";
    int Required = sizeof DefaultDate / sizeof DefaultDate[0];

    DebugLog("%p, %#x, %p, %p, %p, %d, %p", lpLocaleName, dwFlags, lpDate, lpFormat, lpDateStr, cchDate, lpCalendar);

    if (lpDateStr == NULL || cchDate == 0) {
        return Required;
    }

    if (cchDate < Required) {
        return 0;
    }

    memcpy(lpDateStr, DefaultDate, sizeof DefaultDate);
    return Required;
}

STATIC int WINAPI GetTimeFormatEx(PVOID lpLocaleName,
                                  DWORD dwFlags,
                                  PVOID lpTime,
                                  PUSHORT lpFormat,
                                  PUSHORT lpTimeStr,
                                  int cchTime)
{
    static const WCHAR DefaultTime[] = L"00:00:00";
    int Required = sizeof DefaultTime / sizeof DefaultTime[0];

    DebugLog("%p, %#x, %p, %p, %p, %d", lpLocaleName, dwFlags, lpTime, lpFormat, lpTimeStr, cchTime);

    if (lpTimeStr == NULL || cchTime == 0) {
        return Required;
    }

    if (cchTime < Required) {
        return 0;
    }

    memcpy(lpTimeStr, DefaultTime, sizeof DefaultTime);
    return Required;
}

DECLARE_CRT_EXPORT("GetACP", GetACP);
DECLARE_CRT_EXPORT("IsValidCodePage", IsValidCodePage);
DECLARE_CRT_EXPORT("GetCPInfo", GetCPInfo);
DECLARE_CRT_EXPORT("LCIDToLocaleName", LCIDToLocaleName);
DECLARE_CRT_EXPORT("LocaleNameToLCID", LocaleNameToLCID);
DECLARE_CRT_EXPORT("GetUserDefaultLocaleName", GetUserDefaultLocaleName);
DECLARE_CRT_EXPORT("IsValidLocale", IsValidLocale);
DECLARE_CRT_EXPORT("IsValidLocaleName", IsValidLocaleName);
DECLARE_CRT_EXPORT("EnumSystemLocalesEx", EnumSystemLocalesEx);
DECLARE_CRT_EXPORT("LCMapStringA", LCMapStringA);
DECLARE_CRT_EXPORT("LCMapStringW", LCMapStringW);
DECLARE_CRT_EXPORT("LCMapStringEx", LCMapStringEx);
DECLARE_CRT_EXPORT("GetLocaleInfoEx", GetLocaleInfoEx);
DECLARE_CRT_EXPORT("CompareStringEx", CompareStringEx);
DECLARE_CRT_EXPORT("GetDateFormatEx", GetDateFormatEx);
DECLARE_CRT_EXPORT("GetTimeFormatEx", GetTimeFormatEx);
