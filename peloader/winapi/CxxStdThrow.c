/* nika-fuzz dwrite-x86 adapter: the two std bounds-throw helpers that msvcp_win
 * exports and dwrite imports:
 *     ?_Xlength_error@std@@YAXPBD@Z  ->  std::_Xlength_error(const char*)
 *     ?_Xout_of_range@std@@YAXPBD@Z  ->  std::_Xout_of_range(const char*)
 * Each throws the matching std C++ exception so dwrite's own catch (reached on
 * malformed WOFF2 / vector / string input) handles it through loadlibrary's C++
 * EH runtime (CxxException.c) and returns an HRESULT, instead of trapping on an
 * unresolved import.
 *
 * i386 throw tables use absolute 32-bit pointers (no image base). A cross-module
 * catch matches by the mangled type-name string, so each thrown object carries a
 * CatchableType for its whole std hierarchy (length_error/out_of_range ->
 * logic_error -> exception), letting catch(std::exception&), catch(const
 * std::length_error&) and catch(...) all match. The object has a minimal but
 * real MSVC std::exception layout and vtable (scalar-deleting dtor + what()).
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

/* ---- MSVC RTTI / throw structures (i386, absolute pointers) ---- */
typedef void (*vtable_ptr)(void);

typedef struct {
    const vtable_ptr *vtable;
    void             *spare;        /* type_info::name, lazily demangled; unused here */
    char              mangled[64];  /* ".?AV<type>@std@@" */
} type_descriptor;

typedef struct { int mdisp, pdisp, vdisp; } pmd;

typedef struct {
    UINT                   properties;
    const type_descriptor *type;
    pmd                    offsets;
    int                    size;
    void                  *copy_ctor;
} catchable_type;

typedef struct {
    UINT                  count;
    const catchable_type *types[3];
} catchable_type_array;

typedef struct {
    UINT                       attributes;
    void                      *destructor;
    void                      *forward_compat;
    const catchable_type_array *catchable_types;
} throw_info;

/* MSVC std::exception object: { vftable; _What; _DoFree }. */
typedef struct {
    const vtable_ptr *vtable;
    const char       *what;
    int               dofree;
} std_exception;

/* raised by loadlibrary's C++ runtime (CxxException.c) */
extern void __attribute__((stdcall)) CxxThrowException(void *object, const throw_info *info);

/* ---- std::exception vtable: slot 0 scalar-deleting dtor, slot 1 what() ---- */
static void __attribute__((thiscall)) exc_dtor(std_exception *self)
{
    if (self->dofree && self->what)
        free((void *)self->what);
}
static void *__attribute__((thiscall)) exc_vector_dtor(std_exception *self, unsigned flags)
{
    exc_dtor(self);
    if (flags & 1)
        free(self);
    return self;
}
static const char *__attribute__((thiscall)) exc_what(std_exception *self)
{
    return self->what ? self->what : "Unknown exception";
}

static const vtable_ptr std_exception_vtable[] = {
    (vtable_ptr)exc_vector_dtor,
    (vtable_ptr)exc_what,
};

/* copy constructor used if a catch takes the exception by value */
static void *__attribute__((thiscall)) exc_copy_ctor(std_exception *self, const std_exception *src)
{
    self->vtable = std_exception_vtable;
    self->dofree = 0;
    self->what = src->what; /* message is a static string from the caller */
    return self;
}

/* ---- type descriptors for the std hierarchy ---- */
#define DECL_TD(var, mangled_name) \
    static type_descriptor var = { NULL, NULL, mangled_name }
DECL_TD(td_exception,   ".?AVexception@std@@");
DECL_TD(td_logic_error, ".?AVlogic_error@std@@");
DECL_TD(td_length_error, ".?AVlength_error@std@@");
DECL_TD(td_out_of_range, ".?AVout_of_range@std@@");

#define CT(td) { 0, &(td), {0, -1, 0}, (int)sizeof(std_exception), (void *)exc_copy_ctor }
static const catchable_type ct_exception   = CT(td_exception);
static const catchable_type ct_logic_error = CT(td_logic_error);
static const catchable_type ct_length_error = CT(td_length_error);
static const catchable_type ct_out_of_range = CT(td_out_of_range);

static const catchable_type_array cta_length_error = {
    3, { &ct_length_error, &ct_logic_error, &ct_exception }};
static const catchable_type_array cta_out_of_range = {
    3, { &ct_out_of_range, &ct_logic_error, &ct_exception }};

/* ThrowInfo.pmfnUnwind is the exception's cleanup destructor, invoked by the C++
 * runtime as a 1-arg thiscall (call_dtor -> dtor(this)). It must be the scalar
 * destructor exc_dtor, NOT the 2-arg vector-deleting exc_vector_dtor: the latter
 * would read its `flags` argument from uninitialized stack and, when flags&1 is
 * set, free() the stack-allocated exception object. exc_vector_dtor belongs only
 * in the vtable slot, where C++ `delete` passes a real flags value. */
static const throw_info ti_length_error = {
    0, (void *)exc_dtor, NULL, &cta_length_error };
static const throw_info ti_out_of_range = {
    0, (void *)exc_dtor, NULL, &cta_out_of_range };

static void std_throw(const char *msg, const throw_info *ti)
{
    std_exception obj = { std_exception_vtable, msg, 0 };
    CxxThrowException(&obj, ti); /* does not return */
    abort();
}

/* ?_Xlength_error@std@@YAXPBD@Z / ?_Xout_of_range@std@@YAXPBD@Z (__cdecl) */
static void Xlength_error(const char *msg)
{
    DebugLog("std::_Xlength_error(\"%s\")", msg ? msg : "(null)");
    std_throw(msg, &ti_length_error);
}
static void Xout_of_range(const char *msg)
{
    DebugLog("std::_Xout_of_range(\"%s\")", msg ? msg : "(null)");
    std_throw(msg, &ti_out_of_range);
}

DECLARE_CRT_EXPORT("?_Xlength_error@std@@YAXPBD@Z", Xlength_error);
DECLARE_CRT_EXPORT("?_Xout_of_range@std@@YAXPBD@Z", Xout_of_range);
