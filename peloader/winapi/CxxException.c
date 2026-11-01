/* nika-fuzz dwrite-x86 adapter: 32-bit MSVC C++ exception-handling runtime.
 *
 * loadlibrary already owns the i386 SEH dispatch (RaiseException walks fs:0,
 * RtlUnwind runs termination handlers up to a target frame; both in
 * Exception.c, proven against mpengine's statically-linked __CxxFrameHandler3).
 * A module that imports the MSVC C++ runtime instead of static-linking it (this
 * DirectWrite dwrite.dll) needs loadlibrary to PROVIDE that runtime. This file
 * is that runtime: the C++ language handler, the thrower, the unwind helpers,
 * and the SEH4 handler, ported from Wine (dlls/msvcrt/{except_i386.c,except.c,
 * cppexcept.h,cxx.h}) and adapted to loadlibrary's dispatcher and types.
 *
 * i386 uses the NON-RVA table variants: ThrowInfo/FuncInfo hold absolute 32-bit
 * pointers, not image offsets, so there is no image base to add. Cross-module
 * catch type matching is by mangled-name string compare (the TypeDescriptor
 * pointers differ between dwrite and this runtime).
 *
 * Driven by Exception.c's RaiseException: a dwrite __ehhandler thunk loads the
 * FuncInfo into EAX and jumps through the IAT to __CxxFrameHandler3 (the asm
 * trampoline below), which forwards to cxx_frame_handler. On a match the
 * handler runs the catch and transfers control into dwrite via
 * continue_after_catch (it never returns to the dispatcher); with no match it
 * returns ExceptionContinueSearch and the dispatcher walks on.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "util.h"
#include "winexports.h"
#include "exception_internal.h"

#define CXX_EXCEPTION            0xe06d7363
#define CXX_FRAME_MAGIC_VC6      0x19930520
#define CXX_FRAME_MAGIC_VC7      0x19930521
#define CXX_FRAME_MAGIC_VC8      0x19930522
#define CXX_EXCEPTION_PARAMS     3

#define EH_NONCONTINUABLE   0x01
#define EH_UNWINDING        0x02
#define EH_EXIT_UNWIND      0x04

/* catch-type and class flags (cxx.h) */
#define TYPE_FLAG_CONST              1
#define TYPE_FLAG_VOLATILE           2
#define TYPE_FLAG_REFERENCE          8
#define CLASS_IS_SIMPLE_TYPE         1
#define CLASS_HAS_VIRTUAL_BASE_CLASS 4

/* function-descriptor flags (cppexcept.h) */
#define FUNC_DESCR_SYNCHRONOUS  1
#define FUNC_DESCR_NOEXCEPT     4

/* filter dispositions (SEH __except) */
#define FILTER_CONTINUE_EXECUTION  (-1)
#define FILTER_CONTINUE_SEARCH       0
#define FILTER_EXECUTE_HANDLER       1

typedef CONTEXT *PCONTEXT;

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    CONTEXT          *ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

/* ---- RTTI / throw tables (i386, absolute pointers) ---- */
typedef void (*vtable_ptr)(void);

typedef struct __type_info {
    const vtable_ptr *vtable;
    char             *name;         /* demangled, allocated lazily by the owner */
    char              mangled[128]; /* variable length; offset 8 == MSVC TypeDescriptor name */
} type_info;

typedef struct {
    int this_offset;
    int vbase_descr;
    int vbase_offset;
} this_ptr_offsets;

typedef struct {
    UINT                   flags;
    const type_info       *type_info;
    this_ptr_offsets       offsets;
    unsigned int           size;
    void                  *copy_ctor;
} cxx_type_info;

typedef struct {
    UINT                 count;
    const cxx_type_info *info[5]; /* variable length in the module; indexed by count */
} cxx_type_info_table;

typedef struct {
    UINT                       flags;
    void                      *destructor;
    void                      *custom_handler;
    const cxx_type_info_table *type_info_table;
} cxx_exception_type;

/* ---- per-function try/catch descriptor (FuncInfo) ---- */
typedef struct { UINT ip; int state; } ipmap_info;

typedef struct {
    UINT             flags;
    const type_info *type_info;
    int              offset;
    void *         (*handler)(void);
} catchblock_info;

typedef struct {
    int                    start_level;
    int                    end_level;
    int                    catch_level;
    UINT                   catchblock_count;
    const catchblock_info *catchblock;
} tryblock_info;

typedef struct {
    int      prev;
    void * (*handler)(void);
} unwind_info;

typedef struct {
    UINT                 magic : 29;
    UINT                 bbt_flags : 3;
    UINT                 unwind_count;
    const unwind_info   *unwind_table;
    UINT                 tryblock_count;
    const tryblock_info *tryblock;
    UINT                 ipmap_count;
    const ipmap_info    *ipmap;
    const void          *expect_list;
    UINT                 flags;
} cxx_function_descr;

/* the exception frame installed by a function that uses __CxxFrameHandler */
typedef struct __cxx_exception_frame {
    EXCEPTION_FRAME frame;    /* standard registration record (prev, handler) */
    int             trylevel;
    DWORD           ebp;
} cxx_exception_frame;

/* ---- per-thread exception bookkeeping ---- */
typedef struct __frame_info {
    struct __frame_info *next;
    void                *object;
} frame_info;

typedef struct {
    frame_info        frame_info;
    EXCEPTION_RECORD *rec;
    CONTEXT          *context;
} cxx_frame_info;

typedef struct {
    EXCEPTION_RECORD *exc_record;
    CONTEXT          *ctx_record;
    int               processing_throw;
    frame_info       *frame_info_head;
} thread_data_t;

static __thread thread_data_t Cxx_tls;
static thread_data_t *msvcrt_get_thread_data(void) { return &Cxx_tls; }

static void terminate(void) { abort(); }

static inline bool is_cxx_exception(const EXCEPTION_RECORD *rec)
{
    return rec->ExceptionCode == CXX_EXCEPTION &&
           rec->NumberParameters == CXX_EXCEPTION_PARAMS &&
           rec->ExceptionInformation[0] >= CXX_FRAME_MAGIC_VC6 &&
           rec->ExceptionInformation[0] <= CXX_FRAME_MAGIC_VC8;
}

/* ---- fs:0 frame push/pop (loadlibrary keeps the SEH chain in fs:0) ---- */
static inline void push_seh_frame(EXCEPTION_FRAME *f)
{
    EXCEPTION_FRAME *head;
    asm volatile("mov %%fs:0, %0" : "=r"(head));
    f->prev = head;
    asm volatile("mov %0, %%fs:0" :: "r"(f));
}
static inline void pop_seh_frame(EXCEPTION_FRAME *f)
{
    asm volatile("mov %0, %%fs:0" :: "r"(f->prev));
}

/* ---- thiscall ctor/dtor trampolines ---- */
static inline void call_copy_ctor(void *func, void *this, void *src, int has_vbase)
{
    if (has_vbase)
        ((void (__attribute__((thiscall)) *)(void *, void *, int))func)(this, src, 1);
    else
        ((void (__attribute__((thiscall)) *)(void *, void *))func)(this, src);
}
static inline void call_dtor(void *func, void *this)
{
    ((void (__attribute__((thiscall)) *)(void *))func)(this);
}

static inline void *get_this_pointer(const this_ptr_offsets *off, void *object)
{
    if (!object) return NULL;
    if (off->vbase_descr >= 0) {
        int *offset_ptr;
        object = (char *)object + off->vbase_descr;
        offset_ptr = (int *)(*(char **)object + off->vbase_offset);
        object = (char *)object + *offset_ptr;
    }
    object = (char *)object + off->this_offset;
    return object;
}

/* does catch(catch_ti) accept a thrown exc_type? return the matching sub-type */
static const cxx_type_info *find_caught_type(cxx_exception_type *exc_type,
                                             const type_info *catch_ti, UINT catch_flags)
{
    const cxx_type_info_table *table = exc_type->type_info_table;
    UINT i;

    for (i = 0; i < table->count; i++) {
        const cxx_type_info *type = table->info[i];
        const type_info *ti = type->type_info;

        if (!catch_ti) return type;             /* catch(...) */
        if (catch_ti != ti && strcmp(catch_ti->mangled, ti->mangled)) continue;
        if ((exc_type->flags & TYPE_FLAG_CONST) && !(catch_flags & TYPE_FLAG_CONST)) continue;
        if ((exc_type->flags & TYPE_FLAG_VOLATILE) && !(catch_flags & TYPE_FLAG_VOLATILE)) continue;
        return type;
    }
    return NULL;
}

/* copy the thrown object to where the catch block wants it */
static void copy_exception(void *object, void **dest, UINT catch_flags,
                           const cxx_type_info *type)
{
    if (catch_flags & TYPE_FLAG_REFERENCE) {
        *dest = get_this_pointer(&type->offsets, object);
    } else if (type->flags & CLASS_IS_SIMPLE_TYPE) {
        memmove(dest, object, type->size);
        if (type->size == sizeof(void *)) *dest = get_this_pointer(&type->offsets, *dest);
    } else if (type->copy_ctor) {
        call_copy_ctor(type->copy_ctor, dest, get_this_pointer(&type->offsets, object),
                       (type->flags & CLASS_HAS_VIRTUAL_BASE_CLASS));
    } else {
        memmove(dest, get_this_pointer(&type->offsets, object), type->size);
    }
}

static void *find_catch_handler(void *object, uintptr_t frame,
                                const tryblock_info *tryblock, cxx_exception_type *exc_type)
{
    UINT i;
    const catchblock_info *catchblock = tryblock->catchblock;

    for (i = 0; i < tryblock->catchblock_count; i++) {
        const cxx_type_info *type;
        const type_info *catch_ti;

        if (exc_type) {
            catch_ti = catchblock[i].type_info;
            type = find_caught_type(exc_type, catch_ti, catchblock[i].flags);
            if (!type) continue;
            if (catch_ti && catch_ti->mangled[0] && catchblock[i].offset) {
                void **dest = (void **)(frame + catchblock[i].offset);
                copy_exception(object, dest, catchblock[i].flags, type);
            }
        } else {
            if (catchblock[i].type_info) continue; /* only catch(...) for a C exception */
        }
        return (void *)catchblock[i].handler;
    }
    return NULL;
}

/* ---- thread frame-info list (exception object lifetime) ---- */
static frame_info *CreateFrameInfo(frame_info *fi, void *obj)
{
    thread_data_t *data = msvcrt_get_thread_data();
    fi->next = data->frame_info_head;
    data->frame_info_head = fi;
    fi->object = obj;
    return fi;
}
static void FindAndUnlinkFrame(frame_info *fi)
{
    thread_data_t *data = msvcrt_get_thread_data();
    frame_info *cur = data->frame_info_head;
    if (cur == fi) { data->frame_info_head = cur->next; return; }
    for (; cur && cur->next; cur = cur->next)
        if (cur->next == fi) { cur->next = fi->next; return; }
}
static bool is_exception_object_to_be_destroyed(const void *obj)
{
    frame_info *cur;
    for (cur = msvcrt_get_thread_data()->frame_info_head; cur; cur = cur->next)
        if (cur->object == obj) return false;
    return true;
}
static void destruct_exception_object(EXCEPTION_RECORD *rec)
{
    cxx_exception_type *info;
    void *object;
    if (!rec || !is_cxx_exception(rec)) return;
    info = (cxx_exception_type *)rec->ExceptionInformation[2];
    if (!info) return;
    object = (void *)rec->ExceptionInformation[1];
    if (info->destructor) call_dtor(info->destructor, object);
}
static void cxx_unregister_exception_object(cxx_frame_info *fi, bool in_use)
{
    thread_data_t *data = msvcrt_get_thread_data();
    if (fi->rec == (void *)-1) return;
    FindAndUnlinkFrame(&fi->frame_info);
    if (data->exc_record->ExceptionCode == CXX_EXCEPTION && !in_use &&
        is_exception_object_to_be_destroyed((void *)data->exc_record->ExceptionInformation[1]))
        destruct_exception_object(data->exc_record);
    data->exc_record = fi->rec;
    data->ctx_record = fi->context;
}

/* ---- asm helpers (verbatim from Wine's except_i386.c, ELF i386) ---- */
extern void continue_after_catch(cxx_exception_frame *frame, void *addr) __attribute__((noreturn));
extern void call_finally_block(void *code_block, void *base_ptr) __attribute__((noreturn));
extern int  call_filter(int (*func)(PEXCEPTION_POINTERS), void *arg, void *ebp);
extern void *call_handler(void *(*func)(void), void *ebp);

__asm__(
".text\n"
".globl continue_after_catch\n.type continue_after_catch,@function\n"
"continue_after_catch:\n"
"    movl 4(%esp), %edx\n"
"    movl 8(%esp), %eax\n"
"    movl -4(%edx), %esp\n"
"    leal 12(%edx), %ebp\n"
"    jmp *%eax\n"
".globl call_finally_block\n.type call_finally_block,@function\n"
"call_finally_block:\n"
"    movl 8(%esp), %ebp\n"
"    jmp *4(%esp)\n"
".globl call_filter\n.type call_filter,@function\n"
"call_filter:\n"
"    pushl %ebp\n"
"    pushl %ebx\n"
"    pushl %esi\n"
"    pushl %edi\n"
"    pushl 24(%esp)\n"
"    movl 32(%esp), %ebp\n"
"    call *24(%esp)\n"
"    popl %ebp\n"
"    popl %edi\n"
"    popl %esi\n"
"    popl %ebx\n"
"    popl %ebp\n"
"    ret\n"
".globl call_handler\n.type call_handler,@function\n"
"call_handler:\n"
"    pushl %ebp\n"
"    pushl %ebx\n"
"    pushl %esi\n"
"    pushl %edi\n"
"    movl 24(%esp), %ebp\n"
"    call *20(%esp)\n"
"    popl %edi\n"
"    popl %esi\n"
"    popl %ebx\n"
"    popl %ebp\n"
"    ret\n"
);

/* unwind the local function to a given trylevel, running cleanup funclets */
static void cxx_local_unwind(cxx_exception_frame *frame, const cxx_function_descr *descr, int last_level)
{
    void *(*handler)(void);
    int trylevel = frame->trylevel;

    while (trylevel != last_level) {
        if (trylevel < 0 || trylevel >= (int)descr->unwind_count) {
            LogMessage("cxx_local_unwind: invalid trylevel %d", trylevel);
            terminate();
        }
        handler = descr->unwind_table[trylevel].handler;
        if (handler) call_handler(handler, &frame->ebp);
        trylevel = descr->unwind_table[trylevel].prev;
    }
    frame->trylevel = last_level;
}

DWORD cxx_frame_handler(PEXCEPTION_RECORD rec, cxx_exception_frame *frame,
                        PCONTEXT context, EXCEPTION_FRAME **dispatch,
                        const cxx_function_descr *descr, EXCEPTION_FRAME *nested_frame);

/* nested frame installed while a catch funclet runs, for a throw inside catch */
typedef struct {
    EXCEPTION_FRAME           frame;
    cxx_exception_frame      *cxx_frame;
    const cxx_function_descr *descr;
    int                       trylevel;
    cxx_frame_info            frame_info;
} catch_func_nested_frame;

static EXCEPTION_DISPOSITION catch_function_nested_handler(PEXCEPTION_RECORD rec,
        PEXCEPTION_FRAME frame, PCONTEXT context, PEXCEPTION_FRAME *dispatcher)
{
    catch_func_nested_frame *nested = (catch_func_nested_frame *)frame;

    if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)) {
        cxx_unregister_exception_object(&nested->frame_info, false);
        return ExceptionContinueSearch;
    }
    if (rec->ExceptionCode == CXX_EXCEPTION) {
        PEXCEPTION_RECORD prev = msvcrt_get_thread_data()->exc_record;
        if ((rec->ExceptionInformation[1] == 0 && rec->ExceptionInformation[2] == 0) ||
            (prev->ExceptionCode == CXX_EXCEPTION &&
             rec->ExceptionInformation[1] == prev->ExceptionInformation[1] &&
             rec->ExceptionInformation[2] == prev->ExceptionInformation[2])) {
            *rec = *prev;                        /* rethrow */
            rec->ExceptionFlags &= ~EH_UNWINDING;
        }
    }
    return cxx_frame_handler(rec, nested->cxx_frame, context, NULL,
                             nested->descr, &nested->frame);
}

static void check_noexcept(PEXCEPTION_RECORD rec, const cxx_function_descr *descr, bool nested)
{
    if (!nested && rec->ExceptionCode == CXX_EXCEPTION &&
        descr->magic >= CXX_FRAME_MAGIC_VC8 && (descr->flags & FUNC_DESCR_NOEXCEPT)) {
        LogMessage("noexcept function propagating exception");
        terminate();
    }
}

/* find the matching catch, unwind to it, run it, continue after it (no return) */
static void call_catch_block(PEXCEPTION_RECORD rec, CONTEXT *context, cxx_exception_frame *frame,
                             const cxx_function_descr *descr, catch_func_nested_frame *catch_frame,
                             cxx_exception_type *info)
{
    UINT i;
    void *addr, *handler, *object = (void *)rec->ExceptionInformation[1];
    catch_func_nested_frame nested;
    int trylevel = frame->trylevel;
    DWORD save_esp = ((DWORD *)frame)[-1];
    thread_data_t *data = msvcrt_get_thread_data();

    data->processing_throw++;
    for (i = 0; i < descr->tryblock_count; i++) {
        const tryblock_info *tryblock = &descr->tryblock[i];

        if (catch_frame && catch_frame->trylevel > tryblock->start_level) continue;
        if (trylevel < tryblock->start_level) continue;
        if (trylevel > tryblock->end_level) continue;

        handler = find_catch_handler(object, (uintptr_t)&frame->ebp, tryblock, info);
        if (!handler) continue;

        /* keep the exception object alive across the unwind */
        CreateFrameInfo(&nested.frame_info.frame_info, object);

        /* unwind every frame newer than the catching frame (loadlibrary's
         * RtlUnwind runs their handlers, pops them from fs:0, and returns) */
        RtlUnwind(catch_frame ? &catch_frame->frame : &frame->frame, NULL, rec, NULL);
        cxx_local_unwind(frame, descr, tryblock->start_level);
        frame->trylevel = tryblock->end_level + 1;

        nested.frame_info.rec = data->exc_record;
        nested.frame_info.context = data->ctx_record;
        data->exc_record = rec;
        data->ctx_record = context;
        data->processing_throw--;

        nested.frame.handler = (PEXCEPTION_HANDLER)catch_function_nested_handler;
        nested.cxx_frame = frame;
        nested.descr     = descr;
        nested.trylevel  = tryblock->end_level + 1;

        push_seh_frame(&nested.frame);
        addr = call_handler(handler, &frame->ebp);
        pop_seh_frame(&nested.frame);

        ((DWORD *)frame)[-1] = save_esp;
        cxx_unregister_exception_object(&nested.frame_info, false);
        continue_after_catch(frame, addr);   /* no return */
    }
    data->processing_throw--;
}

/* the C++ language handler proper; EAX-passed FuncInfo arrives via the
 * __CxxFrameHandler3 trampoline below */
DWORD cxx_frame_handler(PEXCEPTION_RECORD rec, cxx_exception_frame *frame,
                        PCONTEXT context, EXCEPTION_FRAME **dispatch,
                        const cxx_function_descr *descr, EXCEPTION_FRAME *nested_frame)
{
    cxx_exception_type *exc_type;

    if (descr->magic < CXX_FRAME_MAGIC_VC6 || descr->magic > CXX_FRAME_MAGIC_VC8) {
        LogMessage("cxx_frame_handler: invalid frame magic %x", descr->magic);
        return ExceptionContinueSearch;
    }
    if (descr->magic >= CXX_FRAME_MAGIC_VC8 && (descr->flags & FUNC_DESCR_SYNCHRONOUS) &&
        rec->ExceptionCode != CXX_EXCEPTION)
        return ExceptionContinueSearch;

    if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)) {
        if (descr->unwind_count && !nested_frame) cxx_local_unwind(frame, descr, -1);
        return ExceptionContinueSearch;
    }
    if (!descr->tryblock_count) {
        check_noexcept(rec, descr, nested_frame != NULL);
        return ExceptionContinueSearch;
    }

    if (rec->ExceptionCode == CXX_EXCEPTION &&
        rec->ExceptionInformation[1] == 0 && rec->ExceptionInformation[2] == 0) {
        *rec = *msvcrt_get_thread_data()->exc_record;   /* rethrow */
        rec->ExceptionFlags &= ~EH_UNWINDING;
    }

    if (rec->ExceptionCode == CXX_EXCEPTION) {
        exc_type = (cxx_exception_type *)rec->ExceptionInformation[2];
        if (rec->ExceptionInformation[0] > CXX_FRAME_MAGIC_VC8 && exc_type->custom_handler) {
            /* custom handler form not expected for dwrite; bail to search */
            return ExceptionContinueSearch;
        }
    } else {
        exc_type = NULL;                 /* a non-C++ (SEH) exception: only catch(...) */
    }

    call_catch_block(rec, context, frame, descr,
                     (catch_func_nested_frame *)nested_frame, exc_type);
    check_noexcept(rec, descr, nested_frame != NULL);
    return ExceptionContinueSearch;
}

/* __CxxFrameHandler3: the IAT entry dwrite's __ehhandler thunk jumps to with
 * the FuncInfo in EAX. Push the six cxx_frame_handler args (descr = EAX,
 * nested = 0) and forward. */
extern DWORD CxxFrameHandler3(PEXCEPTION_RECORD, PEXCEPTION_FRAME, PCONTEXT, PEXCEPTION_FRAME *);
__asm__(
".text\n"
".globl CxxFrameHandler3\n.type CxxFrameHandler3,@function\n"
"CxxFrameHandler3:\n"
"    pushl $0\n"           /* nested_frame */
"    pushl %eax\n"         /* descr (FuncInfo from EAX) */
"    pushl 24(%esp)\n"     /* dispatch */
"    pushl 24(%esp)\n"     /* context */
"    pushl 24(%esp)\n"     /* frame */
"    pushl 24(%esp)\n"     /* rec */
"    call cxx_frame_handler\n"
"    add $24, %esp\n"
"    ret\n"
);

/* =====================================================================
 * SEH4 (__try/__except, __try/__finally) language handler
 * ===================================================================== */
typedef struct _SCOPETABLE {
    int     previousTryLevel;
    int   (*lpfnFilter)(PEXCEPTION_POINTERS);
    void *(*lpfnHandler)(void);
} SCOPETABLE, *PSCOPETABLE;

typedef struct MSVCRT_EXCEPTION_FRAME {
    EXCEPTION_FRAME *prev;
    void (*handler)(PEXCEPTION_RECORD, EXCEPTION_FRAME *, PCONTEXT, PEXCEPTION_RECORD);
    PSCOPETABLE scopetable;
    int         trylevel;
    int         _ebp;
    PEXCEPTION_POINTERS xpointers;
} MSVCRT_EXCEPTION_FRAME;

typedef struct {
    int   gs_cookie_offset;
    ULONG gs_cookie_xor;
    int   eh_cookie_offset;
    ULONG eh_cookie_xor;
    SCOPETABLE entries[1];
} SCOPETABLE_V4;

static const SCOPETABLE_V4 *get_scopetable_v4(MSVCRT_EXCEPTION_FRAME *frame, ULONG_PTR cookie)
{
    return (const SCOPETABLE_V4 *)((ULONG_PTR)frame->scopetable ^ cookie);
}

static EXCEPTION_DISPOSITION MSVCRT_nested_handler(PEXCEPTION_RECORD rec, PEXCEPTION_FRAME frame,
                                                   PCONTEXT context, PEXCEPTION_FRAME *dispatch)
{
    if (!(rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)))
        return ExceptionContinueSearch;
    *dispatch = frame;
    return ExceptionCollidedUnwind;
}

static void msvcrt_local_unwind4(ULONG *cookie, MSVCRT_EXCEPTION_FRAME *frame, int trylevel, void *ebp)
{
    EXCEPTION_FRAME reg;
    const SCOPETABLE_V4 *scopetable = get_scopetable_v4(frame, *cookie);

    reg.handler = (PEXCEPTION_HANDLER)MSVCRT_nested_handler;
    push_seh_frame(&reg);
    while (frame->trylevel != -2 && frame->trylevel != trylevel) {
        int level = frame->trylevel;
        frame->trylevel = scopetable->entries[level].previousTryLevel;
        if (!scopetable->entries[level].lpfnFilter)
            call_handler(scopetable->entries[level].lpfnHandler, ebp);
    }
    pop_seh_frame(&reg);
}

int _except_handler4_common(ULONG *cookie, void (*check_cookie)(void),
                            EXCEPTION_RECORD *rec, MSVCRT_EXCEPTION_FRAME *frame,
                            CONTEXT *context, EXCEPTION_FRAME **dispatcher)
{
    int retval, trylevel;
    EXCEPTION_POINTERS exceptPtrs;
    const SCOPETABLE_V4 *scope_table = get_scopetable_v4(frame, *cookie);

    (void)check_cookie; (void)dispatcher;

    if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)) {
        msvcrt_local_unwind4(cookie, frame, -2, &frame->_ebp);
        return ExceptionContinueSearch;
    }

    exceptPtrs.ExceptionRecord = rec;
    exceptPtrs.ContextRecord = context;
    *((DWORD *)frame - 1) = (DWORD)(uintptr_t)&exceptPtrs;
    trylevel = frame->trylevel;

    while (trylevel != -2) {
        if (scope_table->entries[trylevel].lpfnFilter) {
            retval = call_filter(scope_table->entries[trylevel].lpfnFilter, &exceptPtrs, &frame->_ebp);
            if (retval == FILTER_CONTINUE_EXECUTION)
                return ExceptionContinueExecution;
            if (retval == FILTER_EXECUTE_HANDLER) {
                destruct_exception_object(rec);
                RtlUnwind((PEXCEPTION_FRAME)frame, NULL, rec, NULL);
                msvcrt_local_unwind4(cookie, frame, trylevel, &frame->_ebp);
                frame->trylevel = scope_table->entries[trylevel].previousTryLevel;
                call_finally_block(scope_table->entries[trylevel].lpfnHandler, &frame->_ebp);
            }
        }
        trylevel = scope_table->entries[trylevel].previousTryLevel;
    }
    return ExceptionContinueSearch;
}

/* =====================================================================
 * Throwers and UCRT exception-pointer helpers
 * ===================================================================== */
void __attribute__((stdcall)) CxxThrowException(void *object, const cxx_exception_type *type)
{
    ULONG_PTR args[CXX_EXCEPTION_PARAMS];
    args[0] = CXX_FRAME_MAGIC_VC6;
    args[1] = (ULONG_PTR)object;
    args[2] = (ULONG_PTR)type;
    RaiseException(CXX_EXCEPTION, EH_NONCONTINUABLE, CXX_EXCEPTION_PARAMS, args);
    abort(); /* RaiseException does not return for a C++ throw */
}

void **__current_exception(void)        { return (void **)&msvcrt_get_thread_data()->exc_record; }
void **__current_exception_context(void) { return (void **)&msvcrt_get_thread_data()->ctx_record; }
int  *__processing_throw(void)          { return &msvcrt_get_thread_data()->processing_throw; }
void  __std_terminate(void)             { terminate(); }

DECLARE_CRT_EXPORT("__CxxFrameHandler3", CxxFrameHandler3);
DECLARE_CRT_EXPORT("_CxxThrowException", CxxThrowException);
DECLARE_CRT_EXPORT("_except_handler4_common", _except_handler4_common);
DECLARE_CRT_EXPORT("__current_exception", __current_exception);
DECLARE_CRT_EXPORT("__current_exception_context", __current_exception_context);
DECLARE_CRT_EXPORT("__processing_throw", __processing_throw);
DECLARE_CRT_EXPORT("__std_terminate", __std_terminate);
