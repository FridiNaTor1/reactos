/*
* PROJECT:         ReactOS API tests
* LICENSE:         LGPLv2.1+ - See COPYING.LIB in the top level directory
* PURPOSE:         Test for __C_specific_handler
* PROGRAMMER:      Timo Kreuzer <timo.kreuzer@reactos.org>
*/

#include <apitest.h>

#include <pseh/pseh2.h>
#include <excpt.h>
#include <stdlib.h>
#include <stdio.h>
#include <ntndk.h>

extern char __ImageBase;

#if 0
EXCEPTION_DISPOSITION
__cdecl
__C_specific_handler(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    void* EstablisherFrame,
    struct _CONTEXT* ContextRecord,
    struct _DISPATCHER_CONTEXT* DispatcherContext);
#endif

void
PrepareParameters(
    _In_ PCONTEXT Context,
    _Out_ PEXCEPTION_RECORD ExceptionRecord,
    _Out_ PDISPATCHER_CONTEXT DispatcherContext)
{
    PRUNTIME_FUNCTION FunctionEntry;
    CONTEXT LocalContext;
    PEXCEPTION_ROUTINE ExceptionRoutine;
    ULONG64 ImageBase;

    RtlZeroMemory(ExceptionRecord, sizeof(*ExceptionRecord));
    ExceptionRecord->ExceptionCode = STATUS_ACCESS_VIOLATION;
    ExceptionRecord->ExceptionFlags = 0;
    //ExceptionRecord->ExceptionRecord;
    ExceptionRecord->ExceptionAddress = (PVOID)Context->Rip;
    ExceptionRecord->NumberParameters = 0;
    //ExceptionRecord.ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];

    RtlZeroMemory(DispatcherContext, sizeof(*DispatcherContext));

    LocalContext = *Context;

    FunctionEntry = RtlLookupFunctionEntry(Context->Rip,
                                           &ImageBase,
                                           NULL);

    /* Do a virtual unwind to get the next frame */
    ExceptionRoutine = RtlVirtualUnwind(UNW_FLAG_UHANDLER,
                                        ImageBase,
                                        Context->Rip,
                                        FunctionEntry,
                                        &LocalContext,
                                        &DispatcherContext->HandlerData,
                                        &DispatcherContext->EstablisherFrame,
                                        NULL);


    DispatcherContext->ControlPc = Context->Rip;
    DispatcherContext->ImageBase = ImageBase;
    DispatcherContext->FunctionEntry = FunctionEntry;
    DispatcherContext->TargetIp = 0;
    DispatcherContext->ContextRecord = Context;
    DispatcherContext->LanguageHandler = __C_specific_handler;
    DispatcherContext->HistoryTable = 0;
    DispatcherContext->ScopeIndex = 0;

}

#if 0
EXCEPTION_DISPOSITION
__cdecl
Call__C_specific_handler(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    void* EstablisherFrame,
    struct _CONTEXT* ContextRecord)
{
    DISPATCHER_CONTEXT DispatcherContext = { 0 };
    PVOID FunctionEntry;
    PVOID ImageBase;

    FunctionEntry = RtlLookupFunctionEntry(ContextRecord->Rip,
                                           &ImageBase,
                                           NULL);

    DispatcherContext.ControlPc = ContextRecord->Rip;
    DispatcherContext.ImageBase = ImageBase;
    DispatcherContext.FunctionEntry = FunctionEntry;
    //DispatcherContext.EstablisherFrame;
    //DispatcherContext.TargetIp;
    //DispatcherContext.ContextRecord;
    //DispatcherContext.LanguageHandler;
    //DispatcherContext.HandlerData;
    //DispatcherContext.HistoryTable;
    //DispatcherContext.ScopeIndex;


    return __C_specific_handler(ExceptionRecord,
                                EstablisherFrame,
                                &Context,
                                DispatcherContext);
}
#endif

long
__cdecl
TestExceptionStatus(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    void* EstablisherFrame,
    struct _CONTEXT* ContextRecord,
    struct _DISPATCHER_CONTEXT* DispatcherContext)
{
    long Status = 0;

    _SEH2_TRY
    {
        __C_specific_handler(ExceptionRecord,
                             EstablisherFrame,
                             ContextRecord,
                             DispatcherContext);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return Status;
}

void Test_parameters(void)
{
    EXCEPTION_RECORD ExceptionRecord = { 0 };
    ULONG64 EstablisherFrame;
    CONTEXT Context = { 0 };
    DISPATCHER_CONTEXT DispatcherContext = { 0 };
    ULONG FinallyCalled = 0;

    _SEH2_TRY
    {
        RtlCaptureContext(&Context);
    }
    _SEH2_FINALLY
    {
        FinallyCalled++;
    }
    _SEH2_END;

    PrepareParameters(&Context, &ExceptionRecord, &DispatcherContext);
    ExceptionRecord.ExceptionFlags |= EXCEPTION_UNWIND;

    // First something that works
    ok_long(TestExceptionStatus(&ExceptionRecord, &EstablisherFrame, &Context, &DispatcherContext), STATUS_SUCCESS);

    // DispatcherContext cannot be NULL
    ok_long(TestExceptionStatus(&ExceptionRecord, &EstablisherFrame, &Context, &DispatcherContext), STATUS_ACCESS_VIOLATION);

}


START_TEST(__C_specific_handler)
{
    Test_parameters();
}
