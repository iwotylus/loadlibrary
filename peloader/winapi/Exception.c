#ifndef __USE_GNU
# define __USE_GNU
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define EXCEPTION_CONTINUE_EXECUTION    (-1)
#define EXCEPTION_CONTINUE_SEARCH       0
#define EXCEPTION_EXECUTE_HANDLER       1

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    CONTEXT *ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

typedef LONG (WINAPI *LPTOP_LEVEL_EXCEPTION_FILTER)(PEXCEPTION_POINTERS ExceptionInfo);

static LPTOP_LEVEL_EXCEPTION_FILTER TopLevelExceptionFilter;

#define CXX_EXCEPTION_CODE 0xE06D7363

static __thread bool CxxRethrowInProgress;

// engine 1.1.26080 repair: while scanning, the engine's post-unwind code can overwrite
// an SEH registration record's prev field with the record's own address (prev == self),
// turning the fs:0 chain into a cycle. We record each unwind target's valid prev here so
// the dispatcher can repair a self-referential node and continue to the real handler.
#define UNWIND_SHADOW_SLOTS 256
static __thread struct { PEXCEPTION_FRAME frame; PEXCEPTION_FRAME prev; } UnwindShadow[UNWIND_SHADOW_SLOTS];
static __thread unsigned UnwindShadowNext;

static void RememberUnwindTarget(PEXCEPTION_FRAME frame)
{
    if (!frame || frame->prev == frame)
        return;
    for (unsigned i = 0; i < UNWIND_SHADOW_SLOTS; i++) {
        if (UnwindShadow[i].frame == frame) { UnwindShadow[i].prev = frame->prev; return; }
    }
    UnwindShadow[UnwindShadowNext % UNWIND_SHADOW_SLOTS].frame = frame;
    UnwindShadow[UnwindShadowNext % UNWIND_SHADOW_SLOTS].prev  = frame->prev;
    UnwindShadowNext++;
}

static PEXCEPTION_FRAME RecallUnwindPrev(PEXCEPTION_FRAME frame)
{
    for (unsigned i = 0; i < UNWIND_SHADOW_SLOTS; i++)
        if (UnwindShadow[i].frame == frame && UnwindShadow[i].prev != frame)
            return UnwindShadow[i].prev;
    return NULL;
}

#ifndef NDEBUG
// You can use `call DumpExceptionChain()` in gdb, like !exchain in windbg if
// you need to debug exception handling.
VOID DumpExceptionChain(VOID)
{
    PEXCEPTION_FRAME ExceptionList;
    DWORD Depth;

    // Fetch Exception List
    asm("mov %%fs:0, %[list]" : [list] "=r"(ExceptionList));

    DebugLog("ExceptionList %p, Dumping SEH Chain...", ExceptionList);

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                 Depth++, "",
                 ExceptionList,
                 ExceptionList->prev,
                 ExceptionList->handler);
    }
}
#endif

static WINAPI PVOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, PVOID Arguments)
{
    PEXCEPTION_FRAME ExceptionList;
    PEXCEPTION_FRAME Dispatch = NULL;
    DWORD Disposition;
    DWORD Depth;
    CONTEXT Context = {0};
    uintptr_t *Frame = __builtin_frame_address(0);
    EXCEPTION_RECORD Record = {
        .ExceptionCode = dwExceptionCode,
        .ExceptionFlags = dwExceptionFlags,
        .ExceptionAddress = (PVOID) Frame[1],
        .NumberParameters = nNumberOfArguments,
    };

    Context.Ebp = (DWORD) Frame[0];
    Context.Eip = (DWORD) Frame[1];
    Context.Esp = (DWORD) &Frame[2];

    // Setup Record
    memcpy(&Record.ExceptionInformation, Arguments, nNumberOfArguments * sizeof(ULONG));

    // MSVC represents `throw;` with the C++ exception magic but no new object
    // or ThrowInfo. Its handlers pass the original exception record on to
    // RtlUnwind, so preserve the observable rethrow state at this boundary.
    CxxRethrowInProgress = Record.ExceptionCode == CXX_EXCEPTION_CODE
        && Record.NumberParameters >= 3
        && Record.ExceptionInformation[1] == 0
        && Record.ExceptionInformation[2] == 0;

    // No need to log C++ Exceptions, this is the common case.
    if (dwExceptionCode != 0xE06D7363) {
        LogMessage("%#x, %#x, %u, %p", dwExceptionCode, dwExceptionFlags, nNumberOfArguments, Arguments);
    }

    // Fetch Exception List
    asm("mov %%fs:0, %[list]" : [list] "=r"(ExceptionList));

    DebugLog("C++ Exception %#x! ExceptionList %p, Dumping SEH Chain...", dwExceptionCode, ExceptionList);
    DebugLog("code=%#x flags=%#x address=%p args=%#x/%#x/%#x ExceptionList=%p",
             dwExceptionCode,
             dwExceptionFlags,
             Record.ExceptionAddress,
             Record.ExceptionInformation[0],
             Record.ExceptionInformation[1],
             Record.ExceptionInformation[2],
             ExceptionList);

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DWORD Result;

        // engine 1.1.26080 repair: a valid SEH chain is acyclic and NULL-terminated,
        // but this engine's post-unwind scan code overwrites a registration record's
        // prev with its own address (prev == self), which would otherwise spin this
        // walk forever. Restore the record's real prev (captured at the unwind that
        // targeted this frame) and keep dispatching to the true handler. If no shadow
        // entry exists we cannot recover, so fail cleanly rather than hang/segfault.
        if (ExceptionList->prev == ExceptionList) {
            PEXCEPTION_FRAME Fixed = RecallUnwindPrev(ExceptionList);
            if (Fixed && Fixed != ExceptionList) {
                DebugLog("repairing self-referential SEH frame %p: prev %p -> %p",
                         ExceptionList, ExceptionList->prev, Fixed);
                ExceptionList->prev = Fixed;
            } else {
                LogMessage("FATAL: self-referential SEH frame %p (handler %p), no shadow "
                           "prev to repair; see docs/STATUS.md",
                           ExceptionList, ExceptionList->handler);
                errx(EXIT_FAILURE, "mpengine SEH chain corrupted (frame %p)",
                     (void *) ExceptionList);
            }
        }

        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                 Depth++, "",
                 ExceptionList,
                 ExceptionList->prev,
                 ExceptionList->handler);

        Result = ExceptionList->handler(&Record, ExceptionList, &Context, &Dispatch);

        DebugLog("%*s Handler Result: %u, Dispatch: %p", Depth, "", Result, Dispatch);
        DebugLog("handler=%p frame=%p result=%u dispatch=%p",
                 ExceptionList->handler,
                 ExceptionList,
                 Result,
                 Dispatch);

        if (Result == ExceptionContinueSearch) {
            continue;
        }

        // I've never seen any other handler return code with mpengine.
        __debugbreak();
    }

    // Unhandled Exception?
    DebugLog("%u Element SEH Chain Complete.", Depth);

finished:
    // I've never seen this reached, I'm not sure if it works.
    __debugbreak();
    return NULL;
}

#define EH_NONCONTINUABLE   0x01
#define EH_UNWINDING        0x02
#define EH_EXIT_UNWIND      0x04
#define EH_STACK_INVALID    0x08
#define EH_NESTED_CALL      0x10

static WINAPI void RtlUnwind(PEXCEPTION_FRAME TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
{
    PEXCEPTION_FRAME ExceptionList;
    DWORD Depth;
    ucontext_t Context;

    DebugLog("%p, %p, %p, %p", TargetFrame, TargetIp, ExceptionRecord, ReturnValue);
    DebugLog("target=%p target_ip=%p record=%p return=%p",
             TargetFrame,
             TargetIp,
             ExceptionRecord,
             ReturnValue);

    assert(ExceptionRecord);
    assert(TargetFrame);
    assert(TargetIp);

    ExceptionRecord->ExceptionFlags |= EH_UNWINDING;

    // Save current registers
    if (getcontext(&Context) != 0) {
        abort();
    }

    // This was suuuuuuper complicated to get right and make mpengine happy.
    Context.uc_mcontext.gregs[REG_EBP] = ((uintptr_t *)(__builtin_frame_address(0)))[0];
    Context.uc_mcontext.gregs[REG_EIP] = ((uintptr_t *)(__builtin_frame_address(0)))[1];
    Context.uc_mcontext.gregs[REG_ESP] = ((uintptr_t)(__builtin_frame_address(0))) + 8 + 16; // Find esp (+8) then skip args (+4*4)
    Context.uc_mcontext.gregs[REG_EAX] = ((uintptr_t)(ReturnValue));

    // Fetch Exception List
    asm("mov %%fs:0, %[list]" : [list] "=r"(ExceptionList));

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DWORD Result;
        DWORD Dispatch = 0;

        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                 Depth++, "",
                 ExceptionList,
                 ExceptionList->prev,
                 ExceptionList->handler);

        // You don't call the final handler, you just install the new context.
        if (ExceptionList == TargetFrame) {
            PEXCEPTION_FRAME NextFrame = ExceptionList->prev;

            DebugLog("TargetFrame %p == ExceptionList %p, Restore Context", ExceptionList, TargetFrame);
            DebugLog("restoring context at frame=%p eip=%#x esp=%#x ebp=%#x eax=%#x",
                     ExceptionList,
                     Context.uc_mcontext.gregs[REG_EIP],
                     Context.uc_mcontext.gregs[REG_ESP],
                     Context.uc_mcontext.gregs[REG_EBP],
                     Context.uc_mcontext.gregs[REG_EAX]);

            if (CxxRethrowInProgress) {
                DebugLog("unlinking C++ rethrow frame=%p handler=%p next=%p",
                         ExceptionList,
                         ExceptionList->handler,
                         NextFrame);
                asm("mov %[list], %%fs:0" :: [list] "r"(NextFrame));
            }

            RememberUnwindTarget(ExceptionList);

            setcontext(&Context);

            // Should not reach here.
            __debugbreak();
        }

        // Call all handlers before the TargetFrame.
        Result = ExceptionList->handler(ExceptionRecord, ExceptionList, NULL, (PVOID) &Dispatch);

        DebugLog("%*s Result: %u, Dispatch: %p", Depth, "", Result, Dispatch);
        DebugLog("handler=%p frame=%p result=%u dispatch=%#x",
                 ExceptionList->handler,
                 ExceptionList,
                 Result,
                 Dispatch);

        if (Result != ExceptionContinueSearch) {
            // I've never seen any other handler return code with mpengine.
            __debugbreak();
        }

        // Remove handler.
        asm("mov %[list], %%fs:0" :: [list] "r"(ExceptionList->prev));
    }

    // Unhandled C++ Exception?
    __debugbreak();
}

static WINAPI LONG UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
    LogMessage("UnhandledExceptionFilter(%p)", ExceptionInfo);

    if (TopLevelExceptionFilter) {
        return TopLevelExceptionFilter(ExceptionInfo);
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

static WINAPI LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER Filter)
{
    LPTOP_LEVEL_EXCEPTION_FILTER PreviousFilter = TopLevelExceptionFilter;

    LogMessage("SetUnhandledExceptionFilter(%p)", Filter);
    TopLevelExceptionFilter = Filter;

    return PreviousFilter;
}


DECLARE_CRT_EXPORT("RaiseException", RaiseException);
DECLARE_CRT_EXPORT("RtlUnwind", RtlUnwind);
DECLARE_CRT_EXPORT("UnhandledExceptionFilter", UnhandledExceptionFilter);
DECLARE_CRT_EXPORT("SetUnhandledExceptionFilter", SetUnhandledExceptionFilter);
