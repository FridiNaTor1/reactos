/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * PURPOSE:          KDBG commands
 * FILE:             ntoskrnl/kdbg/kdb_ext.c
 * PROGRAMMERS:      Gregor Anich (blight@blight.eu.org)
 *                   Hervé Poussineau
 */

#include <ntddk.h>
#include <wdbgexts.h>

#undef KeGetPcr
#define KeGetPcr() 0xffdff000

#undef PAGE_SIZE
#define PAGE_SIZE KdDebuggerData.MmPageSize
#undef PAGE_ALIGN
#define PAGE_ALIGN(Va) \
  ((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1))

#define NPX_STATE_TO_STRING(state)                           \
                   ((state) == 0x0 ? "Loaded" :              \
                   ((state) == 0xA ? "Not loaded" : "Unknown"))

FORCEINLINE
VOID
Ke386GetGlobalDescriptorTable(_Out_ PVOID Descriptor)
{
    PVOID* desc = (PVOID*)Descriptor;
    __asm__ __volatile__(
        "sgdt %0"
            : "=m" (*desc)
            : /* no input */
            : "memory");
}

FORCEINLINE
USHORT
Ke386GetTr(VOID)
{
    USHORT Tr;
    __asm__("str %0\n\t"
    : "=m" (Tr));
    return Tr;
}

FORCEINLINE
VOID
Ke386GetLocalDescriptorTable(
    _Out_ PVOID Descriptor)
{
    __asm__ __volatile__(
        "sldt %0"
            : "=m" (*((short*)Descriptor))
            : /* no input */
            : "memory");
}

typedef struct _KDESCRIPTOR
{
    USHORT Pad[3];
    USHORT Limit;
    PVOID Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

FORCEINLINE
ULONG_PTR
KeGetContextPc(
    _In_ PCONTEXT Context)
{
#ifdef _M_IX86
    return Context->Eip;
#else
    return Context->Rip;
#endif
}

FORCEINLINE
ULONG_PTR
KeGetContextFrameRegister(
    _In_ PCONTEXT Context)
{
#ifdef _M_IX86
    return Context->Ebp;
#else
    return Context->Rbp;
#endif
}

/*! \brief Print address...
 *
 * Tries to lookup line number, file name and function name for the given
 * address and prints it.
 * If no such information is found the address is printed in the format
 * <module: offset>, otherwise the format will be
 * <module: offset (filename:linenumber (functionname))>
 *
 * \retval TRUE  Module containing \a Address was found, \a Address was printed.
 * \retval FALSE  No module containing \a Address was found, nothing was printed.
 */
static BOOLEAN
KdbSymPrintAddress(
    IN PVOID Address)
{
    CHAR Buffer[256];
    ULONG_PTR Displacement;

    /* Try to get symbol */
    Buffer[0] = '\0';
    GetSymbol(Address, Buffer, &Displacement);

    if (!Buffer[0] == '\0')
        return FALSE;

    dprintf("%s", Buffer);
    return TRUE;
}

static VOID
KdbpPrintUnicodeString(
    _In_ PCUNICODE_STRING String)
{
    ULONG i;

    if ((String == NULL) || (String->Buffer == NULL))
    {
        dprintf("<NULL>");
        return;
    }

    for (i = 0; i < String->Length / sizeof(WCHAR); i++)
    {
        dprintf("%c", (CHAR)String->Buffer[i]);
    }
}

static LONG
KdbpDisassemble(
   IN ULONG_PTR Address,
   IN ULONG IntelSyntax)
{
    ULONG_PTR Offset = Address;
    CHAR Buffer[256];
    if (!Disasm(&Offset, Buffer, FALSE))
        return -1;
    return Offset - Address;
}

/*!\brief Evaluates an expression and displays the result.
 */
DECLARE_API(KdbpCmdEvalExpression)
{
    ULONG64 Result;
    ULONG ul;
    LONG l = 0;
    BOOLEAN Ok;
    PCSTR Remainder;

    if (!*args)
    {
        dprintf("?: Argument required\n");
        return;
    }

    /* Evaluate the expression */
    Ok = GetExpressionEx(args, &Result, &Remainder);
    if (Ok)
    {
        if (Result > 0x00000000ffffffffLL)
        {
            if (Result & 0x8000000000000000LL)
                dprintf("0x%016I64x  %20I64u  %20I64d\n", Result, Result, Result);
            else
                dprintf("0x%016I64x  %20I64u\n", Result, Result);
        }
        else
        {
            ul = (ULONG)Result;

            if (ul <= 0xff && ul >= 0x80)
                l = (LONG)((CHAR)ul);
            else if (ul <= 0xffff && ul >= 0x8000)
                l = (LONG)((SHORT)ul);
            else
                l = (LONG)ul;

            if (l < 0)
                dprintf("0x%08lx  %10lu  %10ld\n", ul, ul, l);
            else
                dprintf("0x%08lx  %10lu\n", ul, ul);
        }
    }
}

/*!\brief Disassembles 10 instructions at eip or given address or
 *        displays 16 dwords from memory at given address.
 */
static VOID
KdbpCmdDisasm(
    IN PCSZ args,
    IN BOOLEAN XMode)
{
    CONTEXT Context;
    ULONG cbBytesRead;
    ULONG Count;
    ULONG64 ul;
    INT i;
    ULONGLONG Result = 0;
    ULONG_PTR Address;
    LONG InstLen;

    if (XMode) /* display memory */
        Count = 16;
    else /* disassemble */
        Count = 10;

    if (!*args)
    {
        if (XMode)
        {
            dprintf("x: Address argument required.\n");
            return;
        }
        GetContext(0, &Context, sizeof(CONTEXT));
        Address = KeGetContextPc(&Context);
    }
    else
    {
        /* Evaluate the expression */
        if (!GetExpressionEx(args, &Result, &args))
            return;
        if (Result > (ULONGLONG)(~((ULONG_PTR)0)))
            dprintf("Warning: Address %I64x is beeing truncated\n",Result);
        Address = (ULONG_PTR)Result;
    }

    /* Check for [L count] part */
    if (*args && *args == 'L')
    {
        if (GetExpressionEx(args + 1, &ul, &args))
            Count = ul;
    }

    if (XMode)
    {
        /* Display dwords */
        ul = 0;

        while (Count > 0)
        {
            if (!KdbSymPrintAddress((PVOID)Address))
                dprintf("<%p>:", (PVOID)Address);
            else
                dprintf(":");

            i = min(4, Count);
            Count -= i;

            while (--i >= 0)
            {
                if (!ReadMemory(Address, &ul, sizeof(ul), &cbBytesRead))
                    dprintf(" ????????");
                else
                    dprintf(" %08x", ul);

                Address += sizeof(ul);
            }

            dprintf("\n");
        }
    }
    else
    {
        /* Disassemble */
        while (Count-- > 0)
        {
            if (!KdbSymPrintAddress((PVOID)Address))
                dprintf("<%08x>: ", Address);
            else
                dprintf(": ");

            InstLen = KdbpDisassemble(Address, FALSE);
            if (InstLen < 0)
            {
                dprintf("<INVALID>\n");
                return;
            }

            dprintf("\n");
            Address += InstLen;
        }
    }
}

DECLARE_API(KdbpCmdDisassemble)
{
    KdbpCmdDisasm(args, FALSE);
}

DECLARE_API(KdbpCmdDisassembleX)
{
    KdbpCmdDisasm(args, TRUE);
}

DECLARE_API(KdbpCmdRegs)
{
    CONTEXT Context;
    INT i;
    static const PCHAR EflagsBits[32] = { " CF", NULL, " PF", " BIT3", " AF", " BIT5",
                                          " ZF", " SF", " TF", " IF", " DF", " OF",
                                          NULL, NULL, " NT", " BIT15", " RF", " VF",
                                          " AC", " VIF", " VIP", " ID", " BIT22",
                                          " BIT23", " BIT24", " BIT25", " BIT26",
                                          " BIT27", " BIT28", " BIT29", " BIT30",
                                          " BIT31" };

    GetContext(0, &Context, sizeof(CONTEXT));

#ifdef _M_IX86
    dprintf("CS:EIP  0x%04x:0x%08x\n"
            "SS:ESP  0x%04x:0x%08x\n"
            "   EAX  0x%08x   EBX  0x%08x\n"
            "   ECX  0x%08x   EDX  0x%08x\n"
            "   ESI  0x%08x   EDI  0x%08x\n"
            "   EBP  0x%08x\n",
            Context.SegCs & 0xFFFF, Context.Eip,
            Context.SegSs, Context.Esp,
            Context.Eax, Context.Ebx,
            Context.Ecx, Context.Edx,
            Context.Esi, Context.Edi,
            Context.Ebp);
#else
    dprintf("CS:RIP  0x%04x:0x%p\n"
            "SS:RSP  0x%04x:0x%p\n"
            "   RAX  0x%p     RBX  0x%p\n"
            "   RCX  0x%p     RDX  0x%p\n"
            "   RSI  0x%p     RDI  0x%p\n"
            "   RBP  0x%p\n",
            Context.SegCs & 0xFFFF, Context.Rip,
            Context.SegSs, Context.Rsp,
            Context.Rax, Context.Rbx,
            Context.Rcx, Context.Rdx,
            Context.Rsi, Context.Rdi,
            Context.Rbp);
#endif
    /* Display the EFlags */
    dprintf("EFLAGS  0x%08x ", Context.EFlags);
    for (i = 0; i < 32; i++)
    {
        if (i == 1)
        {
            if ((Context.EFlags & (1 << 1)) == 0)
                dprintf(" !BIT1");
        }
        else if (i == 12)
        {
            dprintf(" IOPL%d", (Context.EFlags >> 12) & 3);
        }
        else if (i == 13)
        {
        }
        else if ((Context.EFlags & (1 << i)) != 0)
        {
            dprintf(EflagsBits[i]);
        }
    }
    dprintf("\n");
}

DECLARE_API(KdbpCmdSRegs)
{
    CONTEXT Context;
    GetContext(0, &Context, sizeof(CONTEXT));

    dprintf("CS  0x%04x  Index 0x%04x  %cDT RPL%d\n",
            Context.SegCs & 0xffff, (Context.SegCs & 0xffff) >> 3,
            (Context.SegCs & (1 << 2)) ? 'L' : 'G', Context.SegCs & 3);
    dprintf("DS  0x%04x  Index 0x%04x  %cDT RPL%d\n",
            Context.SegDs, Context.SegDs >> 3, (Context.SegDs & (1 << 2)) ? 'L' : 'G', Context.SegDs & 3);
    dprintf("ES  0x%04x  Index 0x%04x  %cDT RPL%d\n",
            Context.SegEs, Context.SegEs >> 3, (Context.SegEs & (1 << 2)) ? 'L' : 'G', Context.SegEs & 3);
    dprintf("FS  0x%04x  Index 0x%04x  %cDT RPL%d\n",
            Context.SegFs, Context.SegFs >> 3, (Context.SegFs & (1 << 2)) ? 'L' : 'G', Context.SegFs & 3);
    dprintf("GS  0x%04x  Index 0x%04x  %cDT RPL%d\n",
            Context.SegGs, Context.SegGs >> 3, (Context.SegGs & (1 << 2)) ? 'L' : 'G', Context.SegGs & 3);
    dprintf("SS  0x%04x  Index 0x%04x  %cDT RPL%d\n",
            Context.SegSs, Context.SegSs >> 3, (Context.SegSs & (1 << 2)) ? 'L' : 'G', Context.SegSs & 3);
}

DECLARE_API(KdbpCmdDRegs)
{
    CONTEXT Context;
    GetContext(0, &Context, sizeof(CONTEXT));

    dprintf("DR0  0x%08x\n"
            "DR1  0x%08x\n"
            "DR2  0x%08x\n"
            "DR3  0x%08x\n"
            "DR6  0x%08x\n"
            "DR7  0x%08x\n",
            Context.Dr0, Context.Dr1, Context.Dr2, Context.Dr3,
            Context.Dr6, Context.Dr7);
}

/*!\brief Displays a backtrace.
 */
DECLARE_API(KdbpCmdBt)
{
    ULONGLONG Result = 0;
    CONTEXT Context;
    ULONG_PTR FramePointer, StackPointer, ProgramCounter;
    ULONG_PTR Address;
    EXTSTACKTRACE StackFrames[50];
    ULONG i, FrameCount;

    if (*args && *args == '*')
    {
        /* Got frame address */
        if (!GetExpressionEx(args, &Result, &args))
            return;
        if (Result > (ULONGLONG)(~((ULONG_PTR)0)))
            dprintf("Warning: Address %I64x is beeing truncated\n",Result);
        FramePointer = StackPointer = ProgramCounter = (ULONG_PTR)Result;
    }
    else if (*args)
    {
        /* Got thread id */
        dprintf("Thread backtrace not supported yet!\n");
        return;
    }
    else
    {
        /* No Frame Address or Thread ID, try printing the function at EIP */
        dprintf("Eip:\n");
        if (!KdbSymPrintAddress((PVOID)KeGetContextPc(&Context)))
            dprintf("<%p>\n", KeGetContextPc(&Context));
        else
            dprintf("\n");

        GetContext(0, &Context, sizeof(CONTEXT));
        FramePointer = StackPointer = KeGetContextFrameRegister(&Context);
        ProgramCounter = KeGetContextPc(&Context);
    }

    /* Get stack trace */
    FrameCount = StackTrace(FramePointer, StackPointer, ProgramCounter, StackFrames, ARRAYSIZE(StackFrames));

    /* Walk through the frames */
    dprintf("Frames:\n");
    for (i = 0; i < FrameCount; i++)
    {
        Address = StackFrames[i].ProgramCounter;

        /* Print the location of the call instruction (assumed 5 bytes length) */
        if (!KdbSymPrintAddress((PVOID)(Address - 5)))
            dprintf("<%08x>\n", Address);
        else
            dprintf("\n");
    }
}

typedef struct _KDP_CMD_PROC_PARAMETERS
{
    BOOLEAN DoList;
    BOOLEAN OnlyOne;
    BOOLEAN Display;
    BOOLEAN Found;
    ULONGLONG RequestedProcessId;
    ULONG64 CurrentProcess;
} KDP_CMD_PROC_PARAMETERS, *PKDP_CMD_PROC_PARAMETERS;

typedef struct _KDP_CMD_THREAD_PARAMETERS
{
    BOOLEAN DoList;
    BOOLEAN OnlyOne;
    BOOLEAN Found;
    ULONGLONG RequestedThreadId;
    ULONG64 CurrentThread;
} KDP_CMD_THREAD_PARAMETERS, *PKDP_CMD_THREAD_PARAMETERS;

static ULONG NTAPI
KdbpCmdProcCallback(
    _In_ PFIELD_INFO pField,
    _In_ PVOID UserContext)
{
    PKDP_CMD_PROC_PARAMETERS Parameters = UserContext;
    ULONG_PTR UniqueProcessId;
    CHAR ImageFileName[16];
    UCHAR PcbState;
    PCHAR State, str1, str2;
    ULONG_PTR Process;

    Process = pField->address;
    InitTypeRead(Process, nt!_EPROCESS);

    UniqueProcessId = ReadField(UniqueProcessId);
    PcbState = ReadField(Pcb.State);
    GetFieldValue(Process, "nt!_EPROCESS", "ImageFileName", ImageFileName);

    State = ((PcbState == 0) ? "In Memory" :
            ((PcbState == 1) ? "Out of Memory" : "In Transition"));

    if (Parameters->DoList)
    {
        if (!Parameters->Found)
        {
            dprintf("  PID         State       Filename\n");
            Parameters->Found = TRUE;
        }

        /* Print process */
        if (Process == Parameters->CurrentProcess)
        {
            str1 = "\x1b[1m*";
            str2 = "\x1b[0m";
        }
        else
        {
            str1 = " ";
            str2 = "";
        }

        dprintf(" %s0x%08x  %-10s  %s%s\n",
                str1,
                UniqueProcessId,
                State,
                ImageFileName,
                str2);
    }
    else if (Parameters->OnlyOne &&
             (UniqueProcessId == Parameters->RequestedProcessId || /* search by process id */
              (Parameters->RequestedProcessId == 0 && Process == Parameters->CurrentProcess))) /* search by process */
    {
        Parameters->Found = TRUE;
        if (Parameters->Display)
        {
            dprintf("%s"
                    "  PID:             0x%08x\n"
                    "  State:           %s (0x%x)\n"
                    "  Image Filename:  %s\n",
                    Process == Parameters->CurrentProcess ? "Current process:\n" : "",
                    UniqueProcessId,
                    State, PcbState,
                    ImageFileName);
        }
        Parameters->CurrentProcess = Process;
        return TRUE;
    }

    return FALSE;
}

static ULONG NTAPI
KdbpCmdThreadCallback(
    _In_ PFIELD_INFO pField,
    _In_ PVOID UserContext)
{
    PKDP_CMD_THREAD_PARAMETERS Parameters = UserContext;
    ULONG_PTR UniqueThreadId;
    ULONG_PTR TcbInitialStack;
    UCHAR TcbState;
#ifndef _M_AMD64
    CHAR TcbNpxState;
#endif
    PCSZ State, str1, str2;
    ULONG_PTR Thread;
    ULONG_PTR Stack, Frame, Pc;
    ULONG cbBytesRead;
    static const PCSZ ThreadStateToString[] =
    {
        "Initialized", "Ready", "Running",
        "Standby", "Terminated", "Waiting",
        "Transition", "DeferredReady"
    };

    Thread = pField->address;
    InitTypeRead(Thread, nt!_ETHREAD);

    UniqueThreadId = ReadField(Cid.UniqueThread);
    TcbState = (ULONG)ReadField(Tcb.State);
    TcbInitialStack = (ULONG_PTR)ReadField(Tcb.InitialStack);
    if (TcbState < ARRAYSIZE(ThreadStateToString))
        State = ThreadStateToString[TcbState];
    else
        State = "Unknown";
#ifndef _M_AMD64
    TcbNpxState = ReadField(Tcb.NpxState);
#endif

    if (Parameters->DoList)
    {
        /* Print thread */
        if (Thread == Parameters->CurrentThread)
        {
            str1 = "\x1b[1m*";
            str2 = "\x1b[0m";
        }
        else
        {
            str1 = " ";
            str2 = "";
        }

        if (!TcbInitialStack)
        {
            /* Thread has no kernel stack (probably terminated) */
            Stack = Frame = 0;
            Pc = 0;
        }
#if 0
        else if (TcbTrapFrame)
        {
            Stack = KeGetTrapFrameStackRegister(TcbTrapFrame);
            Frame = KeGetTrapFrameFrameRegister(TcbTrapFrame);
            Pc = KeGetTrapFramePc(TcbTrapFrame);
        }
#endif
        else
        {
            Stack = ReadField(Tcb.KernelStack);
            ReadMemory(Stack + 4 * sizeof(ULONG_PTR),
                &Frame, sizeof(Frame), &cbBytesRead);
            Pc = 0;

            if (Frame) /* FIXME: Should we attach to the process to read Ebp[1]? */
                ReadMemory(Frame + sizeof(ULONG_PTR), &Pc, sizeof(Pc), &cbBytesRead);
        }

        dprintf(" %s0x%08x  %-11s  %3d     0x%08x  0x%08x  0x%08x%s\n",
                str1,
                UniqueThreadId,
                State,
                (CHAR)ReadField(Tcb.Priority),
                (ULONG)ReadField(Tcb.Affinity),
                Frame,
                Pc,
                str2);
    }
    else if (Parameters->OnlyOne &&
             (UniqueThreadId == Parameters->RequestedThreadId || /* search by thread id */
              (Parameters->RequestedThreadId == 0 && Thread == Parameters->CurrentThread))) /* search by thread */
    {
        Parameters->Found = TRUE;
        dprintf("%s"
                "  TID:            0x%08x\n"
                "  State:          %s (0x%x)\n"
                "  Priority:       %d\n"
                "  Affinity:       0x%08x\n"
                "  Initial Stack:  0x%08x\n"
                "  Stack Limit:    0x%08x\n"
                "  Stack Base:     0x%08x\n"
                "  Kernel Stack:   0x%08x\n"
#ifndef _M_AMD64
                "  NPX State:      %s (0x%x)\n"
#endif
                , (Thread == Parameters->CurrentThread) ? "Current Thread:\n" : ""
                , UniqueThreadId
                , State, TcbState
                , ReadField(Tcb.Priority)
                , ReadField(Tcb.Affinity)
                , TcbInitialStack
                , ReadField(Tcb.StackLimit)
                , ReadField(Tcb.StackBase)
                , ReadField(Tcb.KernelStack)
#ifndef _M_AMD64
                , NPX_STATE_TO_STRING(TcbNpxState), TcbNpxState
#endif
        );
        Parameters->CurrentThread = Thread;
        return TRUE;
    }

    return FALSE;
}

/*!\brief Lists threads or switches to another thread context.
 */
DECLARE_API(KdbpCmdThread)
{
    KDDEBUGGER_DATA64 KdDebuggerData;

    KDP_CMD_PROC_PARAMETERS ParametersProc = {0};
    KDP_CMD_THREAD_PARAMETERS ParametersThread = {0};
    ULONG_PTR Entry;
    ULONG cbBytesRead;

    GetCurrentThreadAddr(0, &ParametersThread.CurrentThread);
    GetCurrentProcessAddr(0, 0, &ParametersProc.CurrentProcess);

    if (!GetDebuggerData(KDBG_TAG, &KdDebuggerData, sizeof(&KdDebuggerData)) ||
        !KdDebuggerData.PsActiveProcessHead.Pointer)
    {
        dprintf("No processes in the system!\n");
        return;
    }

    if (strncmp(args, "list", 4) == 0)
    {
        /* List all processes */
        ParametersThread.DoList = TRUE;
        if (args[4] && !GetExpressionEx(args + 5, &ParametersProc.RequestedProcessId, &args))
        {
            dprintf("thread: '%s' is not a valid process id!\n", args + 5);
            return;
        }
    }
    else
    {
        /* List one thread */
        ParametersThread.OnlyOne = TRUE;
        if (*args && !GetExpressionEx(args, &ParametersThread.RequestedThreadId, &args))
        {
            dprintf("thread: '%s' is not a valid thread id!\n", args);
            return;
        }
    }

    /* Search selected process */
    ParametersProc.OnlyOne = TRUE;
    ReadMemory(KdDebuggerData.PsActiveProcessHead.Pointer, &Entry, sizeof(Entry), &cbBytesRead);
    ListType("nt!_EPROCESS", Entry, 1, "ActiveProcessLinks", &ParametersProc, KdbpCmdProcCallback);
    if (!ParametersProc.Found)
    {
        dprintf("thread: invalid process id!\n");
        return;
    }
    InitTypeRead(ParametersProc.CurrentProcess, nt!_EPROCESS);

    if (ParametersThread.DoList)
        dprintf("  TID         State        Prior.  Affinity    EBP         EIP\n");

    /* Get first thread of selected process */
    Entry = ReadField(ThreadListHead);

    /* Enumerate all threads */
    ListType("nt!_ETHREAD", Entry, 1, "ThreadListEntry", &ParametersThread, KdbpCmdThreadCallback);

    if (ParametersThread.OnlyOne && !ParametersThread.Found)
    {
        dprintf("thread: invalid thread id!\n");
    }
}

/*!\brief Lists processes or switches to another process context.
 */
DECLARE_API(KdbpCmdProc)
{
    KDDEBUGGER_DATA64 KdDebuggerData;
    KDP_CMD_PROC_PARAMETERS Parameters = {0};
    ULONG_PTR Entry;
    ULONG cbBytesRead;

    GetCurrentProcessAddr(0, 0, &Parameters.CurrentProcess);

    if (!GetDebuggerData(KDBG_TAG, &KdDebuggerData, sizeof(&KdDebuggerData)) ||
        !KdDebuggerData.PsActiveProcessHead.Pointer)
    {
        dprintf("No processes in the system!\n");
        return;
    }

    if (strcmp(args, "list") == 0)
    {
        /* List all processes */
        Parameters.DoList = TRUE;
    }
    else
    {
        /* List one process */
        Parameters.OnlyOne = TRUE;
        if (*args && !GetExpressionEx(args, &Parameters.RequestedProcessId, &args))
        {
            dprintf("proc: '%s' is not a valid process id!\n", args);
            return;
        }
    }

    /* Enumerate all processes */
    Parameters.Display = TRUE;
    ReadMemory(KdDebuggerData.PsActiveProcessHead.Pointer, &Entry, sizeof(Entry), &cbBytesRead);
    ListType("nt!_EPROCESS", Entry, 1, "ActiveProcessLinks", &Parameters, KdbpCmdProcCallback);

    if (Parameters.OnlyOne && !Parameters.Found)
        dprintf("proc: invalid process id!\n");
}

typedef struct _KDP_CMD_MOD_PARAMETERS
{
    BOOLEAN OnlyOne;
    BOOLEAN Found;
    ULONG64 Address;
} KDP_CMD_MOD_PARAMETERS, *PKDP_CMD_MOD_PARAMETERS;

static ULONG NTAPI
KdbpCmdModCallback(
    _In_ PFIELD_INFO pField,
    _In_ PVOID UserContext)
{
    PKDP_CMD_MOD_PARAMETERS Parameters = UserContext;
    ULONG_PTR DllBase, SizeOfImage;
    UNICODE_STRING BaseDllName;
    ULONG_PTR LdrEntry;

    LdrEntry = pField->address;
    InitTypeRead(LdrEntry, nt!_LDR_DATA_TABLE_ENTRY);
    DllBase = ReadField(DllBase);
    SizeOfImage = ReadField(SizeOfImage);
    GetFieldValue(LdrEntry, "nt!_LDR_DATA_TABLE_ENTRY", "BaseDllName", BaseDllName);

    if (!Parameters->OnlyOne || (Parameters->OnlyOne && DllBase <= Parameters->Address && Parameters->Address <= DllBase + SizeOfImage))
    {
        if (!Parameters->Found)
            dprintf("  Base      Size      Name\n");

        dprintf("  %X  %08x  ", DllBase, SizeOfImage);
        KdbpPrintUnicodeString(&BaseDllName);
        dprintf("\n");

        Parameters->Found = TRUE;
        if (Parameters->OnlyOne)
            return TRUE;
    }

    return FALSE;
}

/*!\brief Lists loaded modules or the one containing the specified address.
 */
DECLARE_API(KdbpCmdMod)
{
    KDDEBUGGER_DATA64 KdDebuggerData;
    KDP_CMD_MOD_PARAMETERS Parameters = {0};
    ULONG_PTR Entry;
    ULONG cbBytesRead;

    if (!GetDebuggerData(KDBG_TAG, &KdDebuggerData, sizeof(&KdDebuggerData)) ||
        !KdDebuggerData.PsLoadedModuleList.Pointer)
    {
        dprintf("No modules in the system!\n");
        return;
    }

    if (*args)
    {
        Parameters.OnlyOne = TRUE;
        if (!GetExpressionEx(args, &Parameters.Address, &args))
        {
            dprintf("mod: invalid address '%s'\n", args);
            return;
        }
    }

    /* Enumerate all modules */
    ReadMemory(KdDebuggerData.PsLoadedModuleList.Pointer, &Entry, sizeof(Entry), &cbBytesRead);
    ListType("nt!_LDR_DATA_TABLE_ENTRY", Entry, 1, "InLoadOrderLinks", &Parameters, KdbpCmdModCallback);

    if (Parameters.OnlyOne && !Parameters.Found)
    {
        dprintf("mod: no module containing address 0x%x found!\n", Parameters.Address);
    }
}

/*!\brief Displays GDT or LDT.
 */
static VOID
KdbpCmdGdtLdt(
    _In_ BOOLEAN Global)
{
    KDESCRIPTOR Reg;
    ULONG cbBytesRead;
    ULONG SegDesc[2];
    ULONG SegBase;
    ULONG SegLimit;
    PCHAR SegType;
    UCHAR Type, Dpl;
    INT i;
    ULONG ul;

    ul = 0;

    if (Global)
    {
        /* Read GDTR */
        Ke386GetGlobalDescriptorTable(&Reg.Limit);
        i = 8;
    }
    else
    {
        /* Read LDTR */
        Ke386GetLocalDescriptorTable(&Reg.Limit);
        Reg.Base = 0;
        i = 0;
        ul = 1 << 2;
    }

    if (Reg.Limit < 7)
    {
        dprintf("%s descriptor table is empty.\n",
                Global ? "Global" : "Local");
        return;
    }

    dprintf("%cDT Base: 0x%08x  Limit: 0x%04x\n",
            Global ? 'G' : 'L', Reg.Base, Reg.Limit);
    dprintf("  Idx  Sel.    Type         Base        Limit       DPL  Attribs\n");

    for (; (i + sizeof(SegDesc) - 1) <= Reg.Limit; i += 8)
    {
        if (!ReadMemory((ULONG_PTR)Reg.Base + i, SegDesc, sizeof(SegDesc), &cbBytesRead))
        {
            dprintf("Couldn't access memory at 0x%p!\n", (ULONG_PTR)Reg.Base + i);
            return;
        }

        Dpl = ((SegDesc[1] >> 13) & 3);
        Type = ((SegDesc[1] >> 8) & 0xf);

        SegBase = SegDesc[0] >> 16;
        SegBase |= (SegDesc[1] & 0xff) << 16;
        SegBase |= SegDesc[1] & 0xff000000;
        SegLimit = SegDesc[0] & 0x0000ffff;
        SegLimit |= (SegDesc[1] >> 16) & 0xf;

        if ((SegDesc[1] & (1 << 23)) != 0)
        {
            SegLimit *= 4096;
            SegLimit += 4095;
        }
        else
        {
            SegLimit++;
        }

        if ((SegDesc[1] & (1 << 12)) == 0) /* System segment */
        {
            switch (Type)
            {
                case  1: SegType = "TSS16(Avl)";    break;
                case  2: SegType = "LDT";           break;
                case  3: SegType = "TSS16(Busy)";   break;
                case  4: SegType = "CALLGATE16";    break;
                case  5: SegType = "TASKGATE";      break;
                case  6: SegType = "INTGATE16";     break;
                case  7: SegType = "TRAPGATE16";    break;
                case  9: SegType = "TSS32(Avl)";    break;
                case 11: SegType = "TSS32(Busy)";   break;
                case 12: SegType = "CALLGATE32";    break;
                case 14: SegType = "INTGATE32";     break;
                case 15: SegType = "TRAPGATE32";    break;
                default: SegType = "UNKNOWN";       break;
            }

            if (!(Type >= 1 && Type <= 3) &&
                Type != 9 && Type != 11)
            {
                SegBase = 0;
                SegLimit = 0;
            }
        }
        else if ((SegDesc[1] & (1 << 11)) == 0) /* Data segment */
        {
            if ((SegDesc[1] & (1 << 22)) != 0)
                SegType = "DATA32";
            else
                SegType = "DATA16";
        }
        else /* Code segment */
        {
            if ((SegDesc[1] & (1 << 22)) != 0)
                SegType = "CODE32";
            else
                SegType = "CODE16";
        }

        if ((SegDesc[1] & (1 << 15)) == 0) /* Not present */
        {
            dprintf("  %03d  0x%04x  %-11s  [NP]        [NP]        %02d   NP\n",
                    i / 8, i | Dpl | ul, SegType, Dpl);
        }
        else
        {
            dprintf("  %03d  0x%04x  %-11s  0x%08x  0x%08x  %02d  ",
                    i / 8, i | Dpl | ul, SegType, SegBase, SegLimit, Dpl);

            if ((SegDesc[1] & (1 << 12)) == 0) /* System segment */
            {
                /* FIXME: Display system segment */
            }
            else if ((SegDesc[1] & (1 << 11)) == 0) /* Data segment */
            {
                if ((SegDesc[1] & (1 << 10)) != 0) /* Expand-down */
                    dprintf(" E");

                dprintf((SegDesc[1] & (1 << 9)) ? " R/W" : " R");

                if ((SegDesc[1] & (1 << 8)) != 0)
                    dprintf(" A");
            }
            else /* Code segment */
            {
                if ((SegDesc[1] & (1 << 10)) != 0) /* Conforming */
                    dprintf(" C");

                dprintf((SegDesc[1] & (1 << 9)) ? " R/X" : " X");

                if ((SegDesc[1] & (1 << 8)) != 0)
                    dprintf(" A");
            }

            if ((SegDesc[1] & (1 << 20)) != 0)
                dprintf(" AVL");

            dprintf("\n");
        }
    }
}

/*!\brief Displays GDT.
 */
DECLARE_API(KdbpCmdGdt)
{
    KdbpCmdGdtLdt(TRUE);
}

/*!\brief Displays LDT.
 */
DECLARE_API(KdbpCmdLdt)
{
    KdbpCmdGdtLdt(FALSE);
}

/*!\brief Displays IDT.
 */
DECLARE_API(KdbpCmdIdt)
{
    KDESCRIPTOR Reg;
    ULONG cbBytesRead;
    ULONG SegDesc[2];
    ULONG SegBase;
    PCHAR SegType;
    USHORT SegSel;
    UCHAR Dpl;
    INT i;

    /* Read IDTR */
    __sidt(&Reg.Limit);

    if (Reg.Limit < 7)
    {
        dprintf("Interrupt descriptor table is empty.\n");
        return;
    }

    dprintf("IDT Base: 0x%08x  Limit: 0x%04x\n", Reg.Base, Reg.Limit);
    dprintf("  Idx  Type        Seg. Sel.  Offset      DPL\n");

    for (i = 0; (i + sizeof(SegDesc) - 1) <= Reg.Limit; i += 8)
    {
        if (!ReadMemory((ULONG_PTR)Reg.Base + i, SegDesc, sizeof(SegDesc), &cbBytesRead))
        {
            dprintf("Couldn't access memory at 0x%p!\n", (PVOID)((ULONG_PTR)Reg.Base + i));
            return;
        }

        Dpl = ((SegDesc[1] >> 13) & 3);
        if ((SegDesc[1] & 0x1f00) == 0x0500)        /* Task gate */
            SegType = "TASKGATE";
        else if ((SegDesc[1] & 0x1fe0) == 0x0e00)   /* 32 bit Interrupt gate */
            SegType = "INTGATE32";
        else if ((SegDesc[1] & 0x1fe0) == 0x0600)   /* 16 bit Interrupt gate */
            SegType = "INTGATE16";
        else if ((SegDesc[1] & 0x1fe0) == 0x0f00)   /* 32 bit Trap gate */
            SegType = "TRAPGATE32";
        else if ((SegDesc[1] & 0x1fe0) == 0x0700)   /* 16 bit Trap gate */
            SegType = "TRAPGATE16";
        else
            SegType = "UNKNOWN";

        if ((SegDesc[1] & (1 << 15)) == 0) /* not present */
        {
            dprintf("  %03d  %-10s  [NP]       [NP]        %02d\n",
                    i / 8, SegType, Dpl);
        }
        else if ((SegDesc[1] & 0x1f00) == 0x0500) /* Task gate */
        {
            SegSel = SegDesc[0] >> 16;
            dprintf("  %03d  %-10s  0x%04x                 %02d\n",
                    i / 8, SegType, SegSel, Dpl);
        }
        else
        {
            SegSel = SegDesc[0] >> 16;
            SegBase = (SegDesc[1] & 0xffff0000) | (SegDesc[0] & 0x0000ffff);
            dprintf("  %03d  %-10s  0x%04x     0x%08x  %02d\n",
                    i / 8, SegType, SegSel, SegBase, Dpl);
        }
    }
}

/*!\brief Displays the KPCR
 */
DECLARE_API(KdbpCmdPcr)
{
    KDDEBUGGER_DATA64 KdDebuggerData;
    ULONG_PTR Pcr;

    Pcr = KeGetPcr();
    if (!GetDebuggerData(KDBG_TAG, &KdDebuggerData, sizeof(&KdDebuggerData)))
        return;

    dprintf("Current PCR is at 0x%p.\n", Pcr);

    InitTypeRead(Pcr, nt!_KPCR);

#ifdef _M_IX86
    dprintf("  Tib.ExceptionList:         0x%08x\n"
            "  Tib.StackBase:             0x%08x\n"
            "  Tib.StackLimit:            0x%08x\n"
            "  Tib.SubSystemTib:          0x%08x\n"
            "  Tib.FiberData/Version:     0x%08x\n"
            "  Tib.ArbitraryUserPointer:  0x%08x\n"
            "  Tib.Self:                  0x%08x\n"
            "  SelfPcr:                   0x%08x\n"
            "  PCRCB:                     0x%08x\n"
            "  Irql:                      0x%02x\n"
            "  IRR:                       0x%08x\n"
            "  IrrActive:                 0x%08x\n"
            "  IDR:                       0x%08x\n"
            "  KdVersionBlock:            0x%08x\n"
            "  IDT:                       0x%08x\n"
            "  GDT:                       0x%08x\n"
            "  TSS:                       0x%08x\n"
            "  MajorVersion:              0x%04x\n"
            "  MinorVersion:              0x%04x\n"
            "  SetMember:                 0x%08x\n"
            "  StallScaleFactor:          0x%08x\n"
            "  Number:                    0x%02x\n"
            "  L2CacheAssociativity:      0x%02x\n"
            "  VdmAlert:                  0x%08x\n"
            "  L2CacheSize:               0x%08x\n"
            , (ULONG)ReadField(NtTib.ExceptionList), (ULONG)ReadField(NtTib.StackBase), (ULONG)ReadField(NtTib.StackLimit)
            , (ULONG)ReadField(NtTib.SubSystemTib), (ULONG)ReadField(NtTib.FiberData), (ULONG)ReadField(NtTib.ArbitraryUserPointer)
            , (ULONG)ReadField(NtTib.Self)
            , (ULONG)ReadField(SelfPcr)
            , (ULONG)ReadField(Prcb), (ULONG)ReadField(Irql)
            , (ULONG)ReadField(IRR), (ULONG)ReadField(IrrActive), (ULONG)ReadField(IDR)
            , (ULONG)ReadField(KdVersionBlock)
            , (ULONG)ReadField(IDT), (ULONG)ReadField(GDT), (ULONG)ReadField(TSS)
            , (ULONG)ReadField(MajorVersion), (ULONG)ReadField(MinorVersion)
            , (ULONG)ReadField(SetMember)
            , (ULONG)ReadField(StallScaleFactor)
            , (ULONG)ReadField(Number)
            , (ULONG)ReadField(SecondLevelCacheAssociativity)
            , (ULONG)ReadField(VdmAlert)
            , (ULONG)ReadField(SecondLevelCacheSize));
#else
    dprintf("  GdtBase:                       0x%p\n", (PVOID)(ULONG_PTR)ReadField(GdtBase));
    dprintf("  TssBase:                       0x%p\n", (PVOID)(ULONG_PTR)ReadField(TssBase));
    dprintf("  UserRsp:                       0x%p\n", (PVOID)(ULONG_PTR)ReadField(UserRsp));
    dprintf("  Self:                          0x%p\n", (PVOID)(ULONG_PTR)ReadField(Self));
    dprintf("  CurrentPrcb:                   0x%p\n", (PVOID)(ULONG_PTR)ReadField(CurrentPrcb));
    dprintf("  LockArray:                     0x%p\n", (PVOID)(ULONG_PTR)ReadField(LockArray));
    dprintf("  Used_Self:                     0x%p\n", (PVOID)(ULONG_PTR)ReadField(Used_Self));
    dprintf("  IdtBase:                       0x%p\n", (PVOID)(ULONG_PTR)ReadField(IdtBase));
    dprintf("  Irql:                          %u\n", (ULONG)ReadField(Irql));
    dprintf("  SecondLevelCacheAssociativity: 0x%u\n", (ULONG)ReadField(SecondLevelCacheAssociativity));
    dprintf("  ObsoleteNumber:                %u\n", (ULONG)ReadField(ObsoleteNumber));
    dprintf("  MajorVersion:                  0x%x\n", (ULONG)ReadField(MajorVersion));
    dprintf("  MinorVersion:                  0x%x\n", (ULONG)ReadField(MinorVersion));
    dprintf("  StallScaleFactor:              0x%lx\n", (ULONG)ReadField(StallScaleFactor));
    dprintf("  SecondLevelCacheSize:          0x%lx\n", (ULONG)ReadField(SecondLevelCacheSize));
    dprintf("  KdVersionBlock:                0x%p\n", (PVOID)(ULONG_PTR)ReadField(KdVersionBlock));
#endif
}

#ifdef _M_IX86
/*!\brief Displays the TSS
 */
DECLARE_API(KdbpCmdTss)
{
    USHORT TssSelector;
    ULONG_PTR Tss = 0, CurrentTss, Pcr;

    if (*args)
    {
        /*
         * Specified TSS via its selector [selector] or descriptor address [*descaddr].
         * Note that we ignore any other argument values.
         */
        ULONG64 ulValue;

        if (args[0] != '*' || !GetExpressionEx(args + 1, &ulValue, &args))
        {
            dprintf("Invalid TSS specification '%s'.\n", args);
            return;
        }

        /* Descriptor specified */
        TssSelector = 0; // Unknown selector!
        // TODO: Room for improvement: Find the TSS descriptor
        // in the GDT so as to validate it.
        Tss = (ULONG_PTR)ulValue;
        if (!Tss)
        {
            dprintf("Invalid 32-bit TSS descriptor.\n");
            return;
        }
    }

    Pcr = KeGetPcr();
    InitTypeRead(Pcr, nt!_KPCR);
    CurrentTss = ReadField(TSS);

    if (!Tss)
    {
        /* If no TSS was specified, use the current TSS descriptor */
        TssSelector = Ke386GetTr();
        Tss = CurrentTss;
        // NOTE: If everything works OK, Tss is the current TSS corresponding to the TR selector.
    }

    InitTypeRead(Tss, nt!_KTSS);

    dprintf("%s TSS 0x%04x is at 0x%p.\n",
            (Tss == CurrentTss) ? "Current" : "Specified", TssSelector, Tss);
    dprintf("  Backlink:  0x%04x\n"
            "  Ss0:Esp0:  0x%04x:0x%08x\n"
            // NOTE: Ss1:Esp1 and Ss2:Esp2: are in the NotUsed1 field.
            "  CR3:       0x%08x\n"
            "  EFlags:    0x%08x\n"
            "  Eax:       0x%08x\n"
            "  Ebx:       0x%08x\n"
            "  Ecx:       0x%08x\n"
            "  Edx:       0x%08x\n"
            "  Esi:       0x%08x\n"
            "  Edi:       0x%08x\n"
            "  Eip:       0x%08x\n"
            "  Esp:       0x%08x\n"
            "  Ebp:       0x%08x\n"
            "  Cs:        0x%04x\n"
            "  Ss:        0x%04x\n"
            "  Ds:        0x%04x\n"
            "  Es:        0x%04x\n"
            "  Fs:        0x%04x\n"
            "  Gs:        0x%04x\n"
            "  LDT:       0x%04x\n"
            "  Flags:     0x%04x\n"
            "  IoMapBase: 0x%04x\n",
            (ULONG)ReadField(Backlink),
            (ULONG)ReadField(Ss0),
            (ULONG)ReadField(Esp0),
            (ULONG)ReadField(CR3),
            (ULONG)ReadField(EFlags),
            (ULONG)ReadField(Eax),
            (ULONG)ReadField(Ebx),
            (ULONG)ReadField(Ecx),
            (ULONG)ReadField(Edx),
            (ULONG)ReadField(Esi),
            (ULONG)ReadField(Edi),
            (ULONG)ReadField(Eip),
            (ULONG)ReadField(Esp),
            (ULONG)ReadField(Ebp),
            (ULONG)ReadField(Cs),
            (ULONG)ReadField(Ss),
            (ULONG)ReadField(Ds),
            (ULONG)ReadField(Es),
            (ULONG)ReadField(Fs),
            (ULONG)ReadField(Gs),
            (ULONG)ReadField(LDT),
            (ULONG)ReadField(Flags),
            (ULONG)ReadField(IoMapBase));
}
#endif // _M_IX86
