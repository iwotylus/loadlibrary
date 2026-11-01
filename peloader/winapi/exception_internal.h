/* Internal seam between loadlibrary's SEH dispatcher (Exception.c) and the
 * MSVC C++ exception runtime (CxxException.c).
 *
 * Exception.c owns the fs:0 dispatch: RaiseException walks the registration
 * chain calling each frame's handler, and RtlUnwind runs the termination
 * handlers up to a target frame. Both were static and tuned for mpengine's
 * statically-linked __CxxFrameHandler3. A module that imports the C++ runtime
 * (e.g. this DirectWrite dwrite.dll) needs loadlibrary to provide that
 * runtime; CxxException.c does, and it drives the exact same dispatcher, so
 * these two entry points are shared here rather than duplicated.
 */
#ifndef __EXCEPTION_INTERNAL_H
#define __EXCEPTION_INTERNAL_H

#include "winnt_types.h"

/* The i386 SEH dispatcher, implemented in Exception.c.
 *
 * RaiseException walks fs:0 newest-first, calling frame->handler(rec, frame,
 * ctx, &dispatch); a handler returns ExceptionContinueSearch to pass, or
 * transfers control into its catch and never returns. RtlUnwind runs each
 * termination handler with EH_UNWINDING and pops it from fs:0 until it reaches
 * TargetFrame, then returns to its own caller with fs:0 == TargetFrame and the
 * four stdcall arguments cleaned (i386 semantics the C++ runtime relies on). */
WINAPI PVOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags,
                            DWORD nNumberOfArguments, PVOID Arguments);
WINAPI void RtlUnwind(PEXCEPTION_FRAME TargetFrame, PVOID TargetIp,
                      PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);

/* Last-resort backstop. When the fs:0 chain is exhausted with no handler,
 * the dispatcher calls this hook (if set) instead of __debugbreak(); the
 * harness registers one that longjmps back into its per-input loop and counts
 * the escape. A set hook must not return. With no hook the old __debugbreak()
 * behaviour stands. Registered by the host program, not exported to the PE. */
typedef void (*unhandled_cxx_hook_t)(PEXCEPTION_RECORD ExceptionRecord);
void SetUnhandledCxxHook(unhandled_cxx_hook_t fn);

#endif /* __EXCEPTION_INTERNAL_H */
