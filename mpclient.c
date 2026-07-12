//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"

// Any usage limits to prevent bugs disrupting system.
const struct rlimit kUsageLimits[] = {
    [RLIMIT_FSIZE]  = { .rlim_cur = 0x20000000, .rlim_max = 0x20000000 },
    [RLIMIT_CPU]    = { .rlim_cur = 3600,       .rlim_max = RLIM_INFINITY },
    [RLIMIT_CORE]   = { .rlim_cur = 0,          .rlim_max = 0 },
    [RLIMIT_NOFILE] = { .rlim_cur = 32,         .rlim_max = 32 },
};

DWORD (* __rsignal)(PHANDLE KernelHandle, DWORD Code, PVOID Params, DWORD Size);

static bool MatchPattern(const uint8_t *Data, const uint8_t *Pattern,
                         const char *Mask, size_t Length)
{
    for (size_t i = 0; i < Length; i++) {
        if (Mask[i] == 'x' && Data[i] != Pattern[i]) {
            return false;
        }
    }

    return true;
}

static DWORD WINAPI BypassValidateChain(PVOID Input, PVOID Result)
{
    BYTE *Flags = Result;

    // The result contains the Authenticode and timestamp-chain verdicts.
    // The WinAPI compatibility layer deliberately treats both as trusted.
    Flags[12] = TRUE;
    Flags[13] = TRUE;
    return 0;
}

static bool ApplyMpengineCompatibilityPatches(PVOID ImageBase,
                                               PIMAGE_NT_HEADERS PeHeader)
{
    // ValidateChain checks two adjacent flags in its input before doing the
    // internal SymCrypt verification. Absolute addresses, branch distances,
    // and log identifiers are masked because they change when mpengine is
    // rebuilt.
    static const uint8_t ValidateChainPattern[] = {
        0x80, 0x7f, 0x0f, 0x00, 0x74, 0x00,
        0x80, 0x7f, 0x10, 0x00, 0x74, 0x00,
        0xa1, 0, 0, 0, 0,
        0x3d, 0, 0, 0, 0, 0x74, 0x00,
        0xf6, 0x40, 0x1c, 0x01, 0x74, 0x00,
        0x68, 0, 0, 0, 0, 0x6a, 0x00,
        0xff, 0x70, 0x14, 0xff, 0x70, 0x10, 0xe8, 0, 0, 0, 0,
        0x83, 0xc4, 0x10, 0xb8, 0x57, 0x00, 0x07, 0x80,
        0xe9, 0, 0, 0, 0, 0xbe, 0x00, 0x01, 0x0b, 0x80,
    };
    static const char ValidateChainMask[] =
        "xxxxx?xxxxx?x????x????x?xxxxx?x????x?xxxxxxx????"
        "xxxxxxxx????xxxxxx";
    static const uint8_t Prologue[] = { 0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68 };
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(PeHeader);
    uint8_t *Match = NULL;
    uint8_t *MatchSectionStart = NULL;
    uint8_t *Function = NULL;
    size_t Matches = 0;

    _Static_assert(sizeof(ValidateChainMask) == sizeof(ValidateChainPattern) + 1,
                   "ValidateChain pattern and mask lengths differ");

    for (WORD i = 0; i < PeHeader->FileHeader.NumberOfSections; i++, Section++) {
        uint8_t *Start;
        size_t Size;

        if (!(Section->Characteristics & IMAGE_SCN_CNT_CODE)) {
            continue;
        }

        Start = (uint8_t *) ImageBase + Section->VirtualAddress;
        Size = Section->Misc.VirtualSize;
        if (Size < sizeof(ValidateChainPattern)) {
            continue;
        }

        for (size_t Offset = 0; Offset <= Size - sizeof(ValidateChainPattern); Offset++) {
            if (MatchPattern(Start + Offset, ValidateChainPattern,
                             ValidateChainMask, sizeof(ValidateChainPattern))) {
                Match = Start + Offset;
                MatchSectionStart = Start;
                Matches++;
            }
        }
    }

    if (Matches != 1) {
        LogMessage("unable to identify mpengine ValidateChain uniquely (%zu matches)", Matches);
        return false;
    }

    // Locate the nearest standard MSVC exception-handling prologue. Keeping
    // this separate from the semantic signature tolerates changes in local
    // variable layout between compiler builds.
    for (size_t Distance = sizeof(Prologue); Distance <= 128; Distance++) {
        if ((size_t) (Match - MatchSectionStart) < Distance) {
            break;
        }
        uint8_t *Candidate = Match - Distance;
        if (memcmp(Candidate, Prologue, sizeof(Prologue)) == 0) {
            Function = Candidate;
            break;
        }
    }

    if (!Function) {
        LogMessage("failed to install mpengine ValidateChain compatibility hook");
        return false;
    }

    {
        const uintptr_t PageSize = (uintptr_t) getpagesize();
        const uintptr_t PageStart = (uintptr_t) Function & ~(PageSize - 1);
        struct branch Redirect = { .opcode = X86_OPCODE_JMP_NEAR };
        const uintptr_t PageEnd = ((uintptr_t) Function + sizeof(Redirect)
                                   + PageSize - 1) & ~(PageSize - 1);

        Redirect.operand.i = (uintptr_t) BypassValidateChain
                           - (uintptr_t) Function
                           - sizeof(Redirect);
        if (mprotect((PVOID) PageStart, PageEnd - PageStart,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LogMessage("failed to make mpengine ValidateChain page writable");
            return false;
        }

        memcpy(Function, &Redirect, sizeof(Redirect));
        __builtin___clear_cache((char *) Function,
                                (char *) Function + sizeof(Redirect));
        if (mprotect((PVOID) PageStart, PageEnd - PageStart,
                     PROT_READ | PROT_EXEC) != 0) {
            LogMessage("failed to restore mpengine ValidateChain page permissions");
            return false;
        }
    }

    LogMessage("Applied mpengine ValidateChain compatibility hook at RVA %#x",
               (unsigned int) (Function - (uint8_t *) ImageBase));
    return true;
}

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    if (Scan->Flags & SCAN_MEMBERNAME) {
        LogMessage("Scanning archive member %s", Scan->VirusName);
    }
    if (Scan->Flags & SCAN_FILENAME) {
        LogMessage("Scanning %s", Scan->FileName);
    }
    if (Scan->Flags & SCAN_PACKERSTART) {
        LogMessage("Packer %s identified.", Scan->VirusName);
    }
    if (Scan->Flags & SCAN_ENCRYPTED) {
        LogMessage("File is encrypted.");
    }
    if (Scan->Flags & SCAN_CORRUPT) {
        LogMessage("File may be corrupt.");
    }
    if (Scan->Flags & SCAN_FILETYPE) {
        LogMessage("File %s is identified as %s", Scan->FileName, Scan->VirusName);
    }
    if (Scan->Flags & 0x08000022) {
        LogMessage("Threat %s identified.", Scan->VirusName);
    }
    // This may indicate PUA.
    if ((Scan->Flags & 0x40010000) == 0x40010000) {
        LogMessage("Threat %s identified.", Scan->VirusName);
    }
    return 0;
}

static DWORD ReadStream(PVOID this, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    fseek(this, Offset, SEEK_SET);
    *SizeRead = fread(Buffer, 1, Size, this);
    return TRUE;
}

static DWORD GetStreamSize(PVOID this, PULONGLONG FileSize)
{
    fseek(this, 0, SEEK_END);
    *FileSize = ftell(this);
    return TRUE;
}

static PWCHAR GetStreamName(PVOID this)
{
    return L"input";
}

// These are available for pintool.
BOOL __noinline InstrumentationCallback(PVOID ImageStart, SIZE_T ImageSize)
{
    // Prevent the call from being optimized away.
    asm volatile ("");
    return TRUE;
}

int main(int argc, char **argv, char **envp)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;
    HANDLE KernelHandle;
    SCAN_REPLY ScanReply;
    BOOTENGINE_PARAMS BootParams;
    SCANSTREAM_PARAMS ScanParams;
    STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;
    struct pe_image image = {
        .entry  = NULL,
        .name   = "engine/mpengine.dll",
    };

    // Load the mpengine module.
    if (pe_load_library(image.name, &image.image, &image.size) == false) {
        LogMessage("You must add the dll and vdm files to the engine directory");
        return 1;
    }

    // Handle relocations, imports, etc.
    link_pe_images(&image, 1);

    // Fetch the headers to get base offsets.
    DosHeader   = (PIMAGE_DOS_HEADER) image.image;
    PeHeader    = (PIMAGE_NT_HEADERS)(image.image + DosHeader->e_lfanew);

    if (!ApplyMpengineCompatibilityPatches(image.image, PeHeader)) {
        return 1;
    }

    // Load any additional exports.
    if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "engine/mpengine.map")) {
#ifndef NDEBUG
        LogMessage("The map file wasn't found, symbols wont be available");
#endif
    } else {
        // Calculate the commands needed to get export and map symbols visible in gdb.
        if (IsGdbPresent()) {
            LogMessage("GDB: add-symbol-file %s %#x+%#x",
                       image.name,
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode);
            LogMessage("GDB: shell bash genmapsym.sh %#x+%#x symbols_%d.o < %s",
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode,
                       getpid(),
                       "engine/mpengine.map");
            LogMessage("GDB: add-symbol-file symbols_%d.o 0", getpid());
            __debugbreak();
        }
    }

    if (get_export("__rsignal", &__rsignal) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve mpengine entrypoint");
    }

    EXCEPTION_DISPOSITION ExceptionHandler(struct _EXCEPTION_RECORD *ExceptionRecord,
            struct _EXCEPTION_FRAME *EstablisherFrame,
            struct _CONTEXT *ContextRecord,
            struct _EXCEPTION_FRAME **DispatcherContext)
    {
        LogMessage("Toplevel Exception Handler Caught Exception");
        abort();
    }

    VOID ResourceExhaustedHandler(int Signal)
    {
        errx(EXIT_FAILURE, "Resource Limits Exhausted, Signal %s", strsignal(Signal));
    }

    setup_nt_threadinfo(ExceptionHandler);

    // Call DllMain()
    image.entry((PVOID) 'MPEN', DLL_PROCESS_ATTACH, NULL);

    // Install usage limits to prevent system crash.
    setrlimit(RLIMIT_CORE, &kUsageLimits[RLIMIT_CORE]);
    setrlimit(RLIMIT_CPU, &kUsageLimits[RLIMIT_CPU]);
    setrlimit(RLIMIT_FSIZE, &kUsageLimits[RLIMIT_FSIZE]);
    setrlimit(RLIMIT_NOFILE, &kUsageLimits[RLIMIT_NOFILE]);

    signal(SIGXCPU, ResourceExhaustedHandler);
    signal(SIGXFSZ, ResourceExhaustedHandler);

# ifndef NDEBUG
    // Enable Maximum heap checking.
    mcheck_pedantic(NULL);
# endif

    ZeroMemory(&BootParams, sizeof BootParams);
    ZeroMemory(&EngineInfo, sizeof EngineInfo);
    ZeroMemory(&EngineConfig, sizeof EngineConfig);

    BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
    BootParams.Attributes    = BOOT_ATTR_NORMAL;
    BootParams.SignatureLocation = L"engine";
    BootParams.ProductName = L"Legitimate Antivirus";
    EngineConfig.QuarantineLocation = L"quarantine";
    EngineConfig.Inclusions = L"*.*";
    EngineConfig.EngineFlags = 1 << 1;
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;

    DWORD BootResult = __rsignal(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof BootParams);
    if (BootResult != 0) {
        LogMessage("__rsignal(RSIG_BOOTENGINE) returned %#x, missing definitions?", BootResult);
        LogMessage("Make sure the VDM files and mpengine.dll are in the engine directory");
        return 1;
    }

    ZeroMemory(&ScanParams, sizeof ScanParams);
    ZeroMemory(&ScanDescriptor, sizeof ScanDescriptor);
    ZeroMemory(&ScanReply, sizeof ScanReply);

    ScanParams.Descriptor        = &ScanDescriptor;
    ScanParams.ScanReply         = &ScanReply;
    ScanReply.EngineScanCallback = EngineScanCallback;
    ScanReply.field_C            = 0x7fffffff;
    ScanDescriptor.Read          = ReadStream;
    ScanDescriptor.GetSize       = GetStreamSize;
    ScanDescriptor.GetName       = GetStreamName;

    if (argc < 2) {
        LogMessage("usage: %s [filenames...]", *argv);
        return 1;
    }

    // Enable Instrumentation.
    InstrumentationCallback(image.image, image.size);

    for (char *filename = *++argv; *argv; ++argv) {
        ScanDescriptor.UserPtr = fopen(*argv, "r");

        if (ScanDescriptor.UserPtr == NULL) {
            LogMessage("failed to open file %s", *argv);
            return 1;
        }

        LogMessage("Scanning %s...", *argv);

        if (__rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams) != 0) {
            LogMessage("__rsignal(RSIG_SCAN_STREAMBUFFER) returned failure, file unreadable?");
            return 1;
        }

        fclose(ScanDescriptor.UserPtr);
    }

    return 0;
}
