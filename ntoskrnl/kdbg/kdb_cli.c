/*
 *  ReactOS kernel
 *  Copyright (C) 2005 ReactOS Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/kdbg/kdb_cli.c
 * PURPOSE:         Kernel debugger command line interface
 * PROGRAMMER:      Gregor Anich (blight@blight.eu.org)
 *                  Hervé Poussineau
 * UPDATE HISTORY:
 *                  Created 16/01/2005
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include <kdros.h>

#define NDEBUG
#include <debug.h>

/* DEFINES *******************************************************************/

#define KDB_ENTER_CONDITION_TO_STRING(cond)                               \
                   ((cond) == KdbDoNotEnter ? "never" :                   \
                   ((cond) == KdbEnterAlways ? "always" :                 \
                   ((cond) == KdbEnterFromKmode ? "kmode" : "umode")))

#define KDB_ACCESS_TYPE_TO_STRING(type)                                   \
                   ((type) == KdbAccessRead ? "read" :                    \
                   ((type) == KdbAccessWrite ? "write" :                  \
                   ((type) == KdbAccessReadWrite ? "rdwr" : "exec")))

#define NPX_STATE_TO_STRING(state)                                        \
                   ((state) == NPX_STATE_LOADED ? "Loaded" :              \
                   ((state) == NPX_STATE_NOT_LOADED ? "Not loaded" : "Unknown"))

/* PROTOTYPES ****************************************************************/

extern KDBG_EXTENSION_ROUTINE KdbpCmdEvalExpression;
extern KDBG_EXTENSION_ROUTINE KdbpCmdDisassemble;
extern KDBG_EXTENSION_ROUTINE KdbpCmdDisassembleX;
extern KDBG_EXTENSION_ROUTINE KdbpCmdRegs;
extern KDBG_EXTENSION_ROUTINE KdbpCmdSRegs;
extern KDBG_EXTENSION_ROUTINE KdbpCmdDRegs;
extern KDBG_EXTENSION_ROUTINE KdbpCmdBt;

static BOOLEAN KdbpCmdContinue(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdStep(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdBreakPointList(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdEnableDisableClearBreakPoint(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdBreakPoint(ULONG Argc, PCHAR Argv[]);

extern KDBG_EXTENSION_ROUTINE KdbpCmdThread;
extern KDBG_EXTENSION_ROUTINE KdbpCmdProc;

extern KDBG_EXTENSION_ROUTINE KdbpCmdMod;
extern KDBG_EXTENSION_ROUTINE KdbpCmdGdt;
extern KDBG_EXTENSION_ROUTINE KdbpCmdLdt;
extern KDBG_EXTENSION_ROUTINE KdbpCmdIdt;
extern KDBG_EXTENSION_ROUTINE KdbpCmdPcr;
#ifdef _M_IX86
extern KDBG_EXTENSION_ROUTINE KdbpCmdTss;
#endif

static BOOLEAN KdbpCmdBugCheck(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdReboot(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdFilter(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdSet(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdHelp(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdDmesg(ULONG Argc, PCHAR Argv[]);

BOOLEAN ExpKdbgExtPool(ULONG Argc, PCHAR Argv[]);
BOOLEAN ExpKdbgExtPoolUsed(ULONG Argc, PCHAR Argv[]);
BOOLEAN ExpKdbgExtPoolFind(ULONG Argc, PCHAR Argv[]);
BOOLEAN ExpKdbgExtFileCache(ULONG Argc, PCHAR Argv[]);
BOOLEAN ExpKdbgExtDefWrites(ULONG Argc, PCHAR Argv[]);
BOOLEAN ExpKdbgExtIrpFind(ULONG Argc, PCHAR Argv[]);
BOOLEAN ExpKdbgExtHandle(ULONG Argc, PCHAR Argv[]);

extern char __ImageBase;

/* Be more descriptive than intrinsics */
#ifndef Ke386GetGlobalDescriptorTable
# define Ke386GetGlobalDescriptorTable __sgdt
#endif
#ifndef Ke386GetLocalDescriptorTable
# define Ke386GetLocalDescriptorTable __sldt
#endif

/* Portability */
FORCEINLINE
ULONG_PTR
strtoulptr(const char* nptr, char** endptr, int base)
{
#ifdef _M_IX86
    return strtoul(nptr, endptr, base);
#else
    return strtoull(nptr, endptr, base);
#endif
}

/* GLOBALS *******************************************************************/

static KDBG_EXTENSION_API KdbCliExtensions[100] = {
    /* Data */
    { "?", "? expression", "Evaluate expression.", KdbpCmdEvalExpression },
#ifdef _M_IX86 // FIXME: this is broken on x64
    { "disasm", "disasm [address] [L count]", "Disassemble count instructions at address.", KdbpCmdDisassemble },
#endif // _M_IX86
    { "x", "x [address] [L count]", "Display count dwords, starting at address.", KdbpCmdDisassembleX },
    { "regs", "regs", "Display general purpose registers.", KdbpCmdRegs },
    { "sregs", "sregs", "Display status registers.", KdbpCmdSRegs },
    { "dregs","dregs", "Display debug registers.",  KdbpCmdDRegs },
    { "bt", "bt [*frameaddr|thread id]", "Prints current backtrace or from given frame address.", KdbpCmdBt },

    /* Process/Thread */
    { "thread", "thread [list[ pid]|tid]", "List threads in current or specified process, display thread with given id.", KdbpCmdThread },
    { "proc", "proc [list|pid]", "List processes, display process with given id.", KdbpCmdProc },

    /* System info */
    { "mod", "mod [address]", "List all modules or the one containing address.", KdbpCmdMod },
    { "gdt", "gdt", "Display the global descriptor table.", KdbpCmdGdt },
    { "ldt", "ldt", "Display the local descriptor table.", KdbpCmdLdt },
    { "idt", "idt", "Display the interrupt descriptor table.", KdbpCmdIdt },
    { "pcr", "pcr", "Display the processor control region.", KdbpCmdPcr },
#ifdef _M_IX86
    { "tss", "tss [*descaddr]", "Display the current task state segment, or the one specified by its selector number or descriptor address.", KdbpCmdTss },
#endif
    { NULL, NULL, NULL, NULL }
};

static BOOLEAN KdbUseIntelSyntax = FALSE; /* Set to TRUE for intel syntax */
static BOOLEAN KdbBreakOnModuleLoad = FALSE; /* Set to TRUE to break into KDB when a module is loaded */

PCHAR KdbInitFileBuffer = NULL; /* Buffer where KDBinit file is loaded into during initialization */
BOOLEAN KdbpBugCheckRequested = FALSE;

/* Vars for dmesg */
/* defined in ../kd/kdio.c, declare here: */
extern volatile BOOLEAN KdbpIsInDmesgMode;
extern const ULONG KdpDmesgBufferSize;
extern PCHAR KdpDmesgBuffer;
extern volatile ULONG KdpDmesgCurrentPosition;
extern volatile ULONG KdpDmesgFreeBytes;
extern volatile ULONG KdbDmesgTotalWritten;

//
// Debug Filter Component Table
//
#define KD_DEBUG_PRINT_FILTER(Name) \
    { #Name, DPFLTR_##Name##_ID }

static struct
{
    PCSTR Name;
    ULONG Id;
}
ComponentTable[] =
{
//
// Default components
//
    { "WIN2000", MAXULONG },
    KD_DEBUG_PRINT_FILTER(DEFAULT),
//
// Standard components
//
    KD_DEBUG_PRINT_FILTER(SYSTEM),
    KD_DEBUG_PRINT_FILTER(SMSS),
    KD_DEBUG_PRINT_FILTER(SETUP),
    KD_DEBUG_PRINT_FILTER(NTFS),
    KD_DEBUG_PRINT_FILTER(FSTUB),
    KD_DEBUG_PRINT_FILTER(CRASHDUMP),
    KD_DEBUG_PRINT_FILTER(CDAUDIO),
    KD_DEBUG_PRINT_FILTER(CDROM),
    KD_DEBUG_PRINT_FILTER(CLASSPNP),
    KD_DEBUG_PRINT_FILTER(DISK),
    KD_DEBUG_PRINT_FILTER(REDBOOK),
    KD_DEBUG_PRINT_FILTER(STORPROP),
    KD_DEBUG_PRINT_FILTER(SCSIPORT),
    KD_DEBUG_PRINT_FILTER(SCSIMINIPORT),
    KD_DEBUG_PRINT_FILTER(CONFIG),
    KD_DEBUG_PRINT_FILTER(I8042PRT),
    KD_DEBUG_PRINT_FILTER(SERMOUSE),
    KD_DEBUG_PRINT_FILTER(LSERMOUS),
    KD_DEBUG_PRINT_FILTER(KBDHID),
    KD_DEBUG_PRINT_FILTER(MOUHID),
    KD_DEBUG_PRINT_FILTER(KBDCLASS),
    KD_DEBUG_PRINT_FILTER(MOUCLASS),
    KD_DEBUG_PRINT_FILTER(TWOTRACK),
    KD_DEBUG_PRINT_FILTER(WMILIB),
    KD_DEBUG_PRINT_FILTER(ACPI),
    KD_DEBUG_PRINT_FILTER(AMLI),
    KD_DEBUG_PRINT_FILTER(HALIA64),
    KD_DEBUG_PRINT_FILTER(VIDEO),
    KD_DEBUG_PRINT_FILTER(SVCHOST),
    KD_DEBUG_PRINT_FILTER(VIDEOPRT),
    KD_DEBUG_PRINT_FILTER(TCPIP),
    KD_DEBUG_PRINT_FILTER(DMSYNTH),
    KD_DEBUG_PRINT_FILTER(NTOSPNP),
    KD_DEBUG_PRINT_FILTER(FASTFAT),
    KD_DEBUG_PRINT_FILTER(SAMSS),
    KD_DEBUG_PRINT_FILTER(PNPMGR),
    KD_DEBUG_PRINT_FILTER(NETAPI),
    KD_DEBUG_PRINT_FILTER(SCSERVER),
    KD_DEBUG_PRINT_FILTER(SCCLIENT),
    KD_DEBUG_PRINT_FILTER(SERIAL),
    KD_DEBUG_PRINT_FILTER(SERENUM),
    KD_DEBUG_PRINT_FILTER(UHCD),
    KD_DEBUG_PRINT_FILTER(RPCPROXY),
    KD_DEBUG_PRINT_FILTER(AUTOCHK),
    KD_DEBUG_PRINT_FILTER(DCOMSS),
    KD_DEBUG_PRINT_FILTER(UNIMODEM),
    KD_DEBUG_PRINT_FILTER(SIS),
    KD_DEBUG_PRINT_FILTER(FLTMGR),
    KD_DEBUG_PRINT_FILTER(WMICORE),
    KD_DEBUG_PRINT_FILTER(BURNENG),
    KD_DEBUG_PRINT_FILTER(IMAPI),
    KD_DEBUG_PRINT_FILTER(SXS),
    KD_DEBUG_PRINT_FILTER(FUSION),
    KD_DEBUG_PRINT_FILTER(IDLETASK),
    KD_DEBUG_PRINT_FILTER(SOFTPCI),
    KD_DEBUG_PRINT_FILTER(TAPE),
    KD_DEBUG_PRINT_FILTER(MCHGR),
    KD_DEBUG_PRINT_FILTER(IDEP),
    KD_DEBUG_PRINT_FILTER(PCIIDE),
    KD_DEBUG_PRINT_FILTER(FLOPPY),
    KD_DEBUG_PRINT_FILTER(FDC),
    KD_DEBUG_PRINT_FILTER(TERMSRV),
    KD_DEBUG_PRINT_FILTER(W32TIME),
    KD_DEBUG_PRINT_FILTER(PREFETCHER),
    KD_DEBUG_PRINT_FILTER(RSFILTER),
    KD_DEBUG_PRINT_FILTER(FCPORT),
    KD_DEBUG_PRINT_FILTER(PCI),
    KD_DEBUG_PRINT_FILTER(DMIO),
    KD_DEBUG_PRINT_FILTER(DMCONFIG),
    KD_DEBUG_PRINT_FILTER(DMADMIN),
    KD_DEBUG_PRINT_FILTER(WSOCKTRANSPORT),
    KD_DEBUG_PRINT_FILTER(VSS),
    KD_DEBUG_PRINT_FILTER(PNPMEM),
    KD_DEBUG_PRINT_FILTER(PROCESSOR),
    KD_DEBUG_PRINT_FILTER(DMSERVER),
    KD_DEBUG_PRINT_FILTER(SR),
    KD_DEBUG_PRINT_FILTER(INFINIBAND),
    KD_DEBUG_PRINT_FILTER(IHVDRIVER),
    KD_DEBUG_PRINT_FILTER(IHVVIDEO),
    KD_DEBUG_PRINT_FILTER(IHVAUDIO),
    KD_DEBUG_PRINT_FILTER(IHVNETWORK),
    KD_DEBUG_PRINT_FILTER(IHVSTREAMING),
    KD_DEBUG_PRINT_FILTER(IHVBUS),
    KD_DEBUG_PRINT_FILTER(HPS),
    KD_DEBUG_PRINT_FILTER(RTLTHREADPOOL),
    KD_DEBUG_PRINT_FILTER(LDR),
    KD_DEBUG_PRINT_FILTER(TCPIP6),
    KD_DEBUG_PRINT_FILTER(ISAPNP),
    KD_DEBUG_PRINT_FILTER(SHPC),
    KD_DEBUG_PRINT_FILTER(STORPORT),
    KD_DEBUG_PRINT_FILTER(STORMINIPORT),
    KD_DEBUG_PRINT_FILTER(PRINTSPOOLER),
    KD_DEBUG_PRINT_FILTER(VSSDYNDISK),
    KD_DEBUG_PRINT_FILTER(VERIFIER),
    KD_DEBUG_PRINT_FILTER(VDS),
    KD_DEBUG_PRINT_FILTER(VDSBAS),
    KD_DEBUG_PRINT_FILTER(VDSDYN),  // Specified in Vista+
    KD_DEBUG_PRINT_FILTER(VDSDYNDR),
    KD_DEBUG_PRINT_FILTER(VDSLDR),  // Specified in Vista+
    KD_DEBUG_PRINT_FILTER(VDSUTIL),
    KD_DEBUG_PRINT_FILTER(DFRGIFC),
    KD_DEBUG_PRINT_FILTER(MM),
    KD_DEBUG_PRINT_FILTER(DFSC),
    KD_DEBUG_PRINT_FILTER(WOW64),
//
// Components specified in Vista+, some of which we also use in ReactOS
//
    KD_DEBUG_PRINT_FILTER(ALPC),
    KD_DEBUG_PRINT_FILTER(WDI),
    KD_DEBUG_PRINT_FILTER(PERFLIB),
    KD_DEBUG_PRINT_FILTER(KTM),
    KD_DEBUG_PRINT_FILTER(IOSTRESS),
    KD_DEBUG_PRINT_FILTER(HEAP),
    KD_DEBUG_PRINT_FILTER(WHEA),
    KD_DEBUG_PRINT_FILTER(USERGDI),
    KD_DEBUG_PRINT_FILTER(MMCSS),
    KD_DEBUG_PRINT_FILTER(TPM),
    KD_DEBUG_PRINT_FILTER(THREADORDER),
    KD_DEBUG_PRINT_FILTER(ENVIRON),
    KD_DEBUG_PRINT_FILTER(EMS),
    KD_DEBUG_PRINT_FILTER(WDT),
    KD_DEBUG_PRINT_FILTER(FVEVOL),
    KD_DEBUG_PRINT_FILTER(NDIS),
    KD_DEBUG_PRINT_FILTER(NVCTRACE),
    KD_DEBUG_PRINT_FILTER(LUAFV),
    KD_DEBUG_PRINT_FILTER(APPCOMPAT),
    KD_DEBUG_PRINT_FILTER(USBSTOR),
    KD_DEBUG_PRINT_FILTER(SBP2PORT),
    KD_DEBUG_PRINT_FILTER(COVERAGE),
    KD_DEBUG_PRINT_FILTER(CACHEMGR),
    KD_DEBUG_PRINT_FILTER(MOUNTMGR),
    KD_DEBUG_PRINT_FILTER(CFR),
    KD_DEBUG_PRINT_FILTER(TXF),
    KD_DEBUG_PRINT_FILTER(KSECDD),
    KD_DEBUG_PRINT_FILTER(FLTREGRESS),
    KD_DEBUG_PRINT_FILTER(MPIO),
    KD_DEBUG_PRINT_FILTER(MSDSM),
    KD_DEBUG_PRINT_FILTER(UDFS),
    KD_DEBUG_PRINT_FILTER(PSHED),
    KD_DEBUG_PRINT_FILTER(STORVSP),
    KD_DEBUG_PRINT_FILTER(LSASS),
    KD_DEBUG_PRINT_FILTER(SSPICLI),
    KD_DEBUG_PRINT_FILTER(CNG),
    KD_DEBUG_PRINT_FILTER(EXFAT),
    KD_DEBUG_PRINT_FILTER(FILETRACE),
    KD_DEBUG_PRINT_FILTER(XSAVE),
    KD_DEBUG_PRINT_FILTER(SE),
    KD_DEBUG_PRINT_FILTER(DRIVEEXTENDER),
//
// Components specified in Windows 8
//
    KD_DEBUG_PRINT_FILTER(POWER),
    KD_DEBUG_PRINT_FILTER(CRASHDUMPXHCI),
    KD_DEBUG_PRINT_FILTER(GPIO),
    KD_DEBUG_PRINT_FILTER(REFS),
    KD_DEBUG_PRINT_FILTER(WER),
//
// Components specified in Windows 10
//
    KD_DEBUG_PRINT_FILTER(CAPIMG),
    KD_DEBUG_PRINT_FILTER(VPCI),
    KD_DEBUG_PRINT_FILTER(STORAGECLASSMEMORY),
    KD_DEBUG_PRINT_FILTER(FSLIB),
};
#undef KD_DEBUG_PRINT_FILTER

//
// Command Table
//
static const struct
{
    PCHAR Name;
    PCHAR Syntax;
    PCHAR Help;
    BOOLEAN (*Fn)(ULONG Argc, PCHAR Argv[]);
} KdbDebuggerCommands[] = {
    /* Flow control */
    { NULL, NULL, "Flow control", NULL },
    { "cont", "cont", "Continue execution (leave debugger).", KdbpCmdContinue },
    { "step", "step [count]", "Execute single instructions, stepping into interrupts.", KdbpCmdStep },
    { "next", "next [count]", "Execute single instructions, skipping calls and reps.", KdbpCmdStep },
    { "bl", "bl", "List breakpoints.", KdbpCmdBreakPointList },
    { "be", "be [breakpoint]", "Enable breakpoint.", KdbpCmdEnableDisableClearBreakPoint },
    { "bd", "bd [breakpoint]", "Disable breakpoint.", KdbpCmdEnableDisableClearBreakPoint },
    { "bc", "bc [breakpoint]", "Clear breakpoint.", KdbpCmdEnableDisableClearBreakPoint },
    { "bpx", "bpx [address] [IF condition]", "Set software execution breakpoint at address.", KdbpCmdBreakPoint },
    { "bpm", "bpm [r|w|rw|x] [byte|word|dword] [address] [IF condition]", "Set memory breakpoint at address.", KdbpCmdBreakPoint },

    /* Others */
    { NULL, NULL, "Others", NULL },
    { "bugcheck", "bugcheck", "Bugchecks the system.", KdbpCmdBugCheck },
    { "reboot", "reboot", "Reboots the system.", KdbpCmdReboot},
    { "filter", "filter [error|warning|trace|info|level]+|-[componentname|default]", "Enable/disable debug channels.", KdbpCmdFilter },
    { "set", "set [var] [value]", "Sets var to value or displays value of var.", KdbpCmdSet },
    { "dmesg", "dmesg", "Display debug messages on screen, with navigation on pages.", KdbpCmdDmesg },
    { "kmsg", "kmsg", "Kernel dmesg. Alias for dmesg.", KdbpCmdDmesg },
    { "help", "help", "Display help screen.", KdbpCmdHelp },
    { "!pool", "!pool [Address [Flags]]", "Display information about pool allocations.", ExpKdbgExtPool },
    { "!poolused", "!poolused [Flags [Tag]]", "Display pool usage.", ExpKdbgExtPoolUsed },
    { "!poolfind", "!poolfind Tag [Pool]", "Search for pool tag allocations.", ExpKdbgExtPoolFind },
    { "!filecache", "!filecache", "Display cache usage.", ExpKdbgExtFileCache },
    { "!defwrites", "!defwrites", "Display cache write values.", ExpKdbgExtDefWrites },
    { "!irpfind", "!irpfind [Pool [startaddress [criteria data]]]", "Lists IRPs potentially matching criteria.", ExpKdbgExtIrpFind },
    { "!handle", "!handle [Handle]", "Displays info about handles.", ExpKdbgExtHandle },
};

//
// Known fields table
//
typedef struct _KDP_KNOWN_FIELD
{
    PCSZ Type;
    PCSZ Field;
    ULONGLONG Offset;
    ULONG Size;
} KDP_KNOWN_FIELD, *PKDP_KNOWN_FIELD;

static const KDP_KNOWN_FIELD KdbKnownFields[] = {
#define KNOWN_FIELD(s, f) { #s, #f, FIELD_OFFSET(s, f), sizeof(((s*)NULL)->f) }
    KNOWN_FIELD(EPROCESS, ActiveProcessLinks),
    KNOWN_FIELD(EPROCESS, ImageFileName),
    KNOWN_FIELD(EPROCESS, UniqueProcessId),
    KNOWN_FIELD(EPROCESS, Pcb.State),
    KNOWN_FIELD(EPROCESS, ThreadListHead),
    KNOWN_FIELD(ETHREAD, ThreadListEntry),
    KNOWN_FIELD(ETHREAD, Cid.UniqueThread),
    KNOWN_FIELD(ETHREAD, Tcb.InitialStack),
    KNOWN_FIELD(ETHREAD, Tcb.KernelStack),
    KNOWN_FIELD(ETHREAD, Tcb.StackBase),
    KNOWN_FIELD(ETHREAD, Tcb.StackLimit),
    KNOWN_FIELD(ETHREAD, Tcb.Priority),
    KNOWN_FIELD(ETHREAD, Tcb.State),
    KNOWN_FIELD(ETHREAD, Tcb.Affinity),
    KNOWN_FIELD(ETHREAD, Tcb.NpxState),
    KNOWN_FIELD(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
    KNOWN_FIELD(LDR_DATA_TABLE_ENTRY, DllBase),
    KNOWN_FIELD(LDR_DATA_TABLE_ENTRY, SizeOfImage),
    KNOWN_FIELD(LDR_DATA_TABLE_ENTRY, BaseDllName),
#ifdef _M_IX86
    KNOWN_FIELD(KPCR, SecondLevelCacheSize),
    KNOWN_FIELD(KPCR, VdmAlert),
    KNOWN_FIELD(KPCR, NtTib.ExceptionList),
    KNOWN_FIELD(KPCR, NtTib.StackBase),
    KNOWN_FIELD(KPCR, NtTib.StackLimit),
    KNOWN_FIELD(KPCR, NtTib.SubSystemTib),
    KNOWN_FIELD(KPCR, NtTib.FiberData),
    KNOWN_FIELD(KPCR, NtTib.ArbitraryUserPointer),
    KNOWN_FIELD(KPCR, NtTib.Self),
    KNOWN_FIELD(KPCR, SelfPcr),
    KNOWN_FIELD(KPCR, Prcb),
    KNOWN_FIELD(KPCR, Irql),
    KNOWN_FIELD(KPCR, IRR),
    KNOWN_FIELD(KPCR, IrrActive),
    KNOWN_FIELD(KPCR, IDR),
    KNOWN_FIELD(KPCR, KdVersionBlock),
    KNOWN_FIELD(KPCR, IDT),
    KNOWN_FIELD(KPCR, GDT),
    KNOWN_FIELD(KPCR, TSS),
    KNOWN_FIELD(KPCR, MajorVersion),
    KNOWN_FIELD(KPCR, MinorVersion),
    KNOWN_FIELD(KPCR, SetMember),
    KNOWN_FIELD(KPCR, StallScaleFactor),
    KNOWN_FIELD(KPCR, Number),
    KNOWN_FIELD(KPCR, SecondLevelCacheAssociativity),
    KNOWN_FIELD(KPCR, VdmAlert),
    KNOWN_FIELD(KPCR, SecondLevelCacheSize),
#else
    KNOWN_FIELD(KPCR, GdtBase),
    KNOWN_FIELD(KPCR, TssBase),
    KNOWN_FIELD(KPCR, UserRsp),
    KNOWN_FIELD(KPCR, Self),
    KNOWN_FIELD(KPCR, CurrentPrcb),
    KNOWN_FIELD(KPCR, LockArray),
    KNOWN_FIELD(KPCR, Used_Self),
    KNOWN_FIELD(KPCR, IdtBase),
    KNOWN_FIELD(KPCR, Irql),
    KNOWN_FIELD(KPCR, SecondLevelCacheAssociativity),
    KNOWN_FIELD(KPCR, ObsoleteNumber),
    KNOWN_FIELD(KPCR, MajorVersion),
    KNOWN_FIELD(KPCR, MinorVersion),
    KNOWN_FIELD(KPCR, StallScaleFactor),
    KNOWN_FIELD(KPCR, SecondLevelCacheSize),
    KNOWN_FIELD(KPCR, KdVersionBlock),
#endif
};

static const KDP_KNOWN_FIELD*
KdbpGetKnownField(
    _In_ PCSZ Type,
    _In_ PCSZ Field)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(KdbKnownFields); i++)
    {
        if (strcmp(Type, KdbKnownFields[i].Type) == 0 &&
            strcmp(Field, KdbKnownFields[i].Field) == 0)
        {
            return &KdbKnownFields[i];
        }
    }
    return NULL;
}

/* FUNCTIONS *****************************************************************/

/*!\brief Evaluates an expression...
 *
 * Much like KdbpRpnEvaluateExpression, but prints the error message (if any)
 * at the given offset.
 *
 * \param Expression  Expression to evaluate.
 * \param ErrOffset   Offset (in characters) to print the error message at.
 * \param Result      Receives the result on success.
 *
 * \retval TRUE   Success.
 * \retval FALSE  Failure.
 */
static BOOLEAN
KdbpEvaluateExpression(
    IN  PCSZ Expression,
    IN  LONG ErrOffset,
    OUT PULONGLONG Result)
{
    static CHAR ErrMsgBuffer[130] = "^ ";
    LONG ExpressionErrOffset = -1;
    PCHAR ErrMsg = ErrMsgBuffer;
    BOOLEAN Ok;

    Ok = KdbpRpnEvaluateExpression(Expression, KdbCurrentContext, Result,
                                   &ExpressionErrOffset, ErrMsgBuffer + 2);
    if (!Ok)
    {
        if (ExpressionErrOffset >= 0)
            ExpressionErrOffset += ErrOffset;
        else
            ErrMsg += 2;

        KdbpPrint("%*s%s\n", ExpressionErrOffset, "", ErrMsg);
    }

    return Ok;
}

BOOLEAN
NTAPI
KdbpGetHexNumber(
    IN PCHAR pszNum,
    OUT ULONG_PTR *pulValue)
{
    char *endptr;

    /* Skip optional '0x' prefix */
    if ((pszNum[0] == '0') && ((pszNum[1] == 'x') || (pszNum[1] == 'X')))
        pszNum += 2;

    /* Make a number from the string (hex) */
    *pulValue = strtoul(pszNum, &endptr, 16);

    return (*endptr == '\0');
}

/*!\brief Retrieves the component ID corresponding to a given component name.
 *
 * \param ComponentName  The name of the component.
 * \param ComponentId    Receives the component id on success.
 *
 * \retval TRUE   Success.
 * \retval FALSE  Failure.
 */
static BOOLEAN
KdbpGetComponentId(
    IN  PCSTR ComponentName,
    OUT PULONG ComponentId)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(ComponentTable); i++)
    {
        if (_stricmp(ComponentName, ComponentTable[i].Name) == 0)
        {
            *ComponentId = ComponentTable[i].Id;
            return TRUE;
        }
    }

    return FALSE;
}

/*!\brief Displays the list of active debug channels, or enable/disable debug channels.
 */
static BOOLEAN
KdbpCmdFilter(
    ULONG Argc,
    PCHAR Argv[])
{
    ULONG i, j, ComponentId, Level;
    ULONG set = DPFLTR_MASK, clear = DPFLTR_MASK;
    PCHAR pend;
    PCSTR opt, p;

    static struct
    {
        PCSTR Name;
        ULONG Level;
    }
    debug_classes[] =
    {
        { "error",   1 << DPFLTR_ERROR_LEVEL   },
        { "warning", 1 << DPFLTR_WARNING_LEVEL },
        { "trace",   1 << DPFLTR_TRACE_LEVEL   },
        { "info",    1 << DPFLTR_INFO_LEVEL    },
    };

    if (Argc <= 1)
    {
        /* Display the list of available debug filter components */
        KdbpPrint("REMARKS:\n"
                  "- The 'WIN2000' system-wide debug filter component is used for DbgPrint()\n"
                  "  messages without Component ID and Level.\n"
                  "- The 'DEFAULT' debug filter component is used for DbgPrint() messages with\n"
                  "  an unknown Component ID.\n\n");
        KdbpPrint("The list of debug filter components currently available on your system is:\n\n");
        KdbpPrint("    Component Name         Component ID\n"
                  "  ==================     ================\n");
        for (i = 0; i < RTL_NUMBER_OF(ComponentTable); i++)
        {
            KdbpPrint("%20s        0x%08lx\n", ComponentTable[i].Name, ComponentTable[i].Id);
        }
        return TRUE;
    }

    for (i = 1; i < Argc; i++)
    {
        opt = Argv[i];
        p = opt + strcspn(opt, "+-");
        if (!p[0]) p = opt; /* Assume it's a debug channel name */

        if (p > opt)
        {
            for (j = 0; j < RTL_NUMBER_OF(debug_classes); j++)
            {
                SIZE_T len = strlen(debug_classes[j].Name);
                if (len != (p - opt))
                    continue;
                if (_strnicmp(opt, debug_classes[j].Name, len) == 0) /* Found it */
                {
                    if (*p == '+')
                        set |= debug_classes[j].Level;
                    else
                        clear |= debug_classes[j].Level;
                    break;
                }
            }
            if (j == RTL_NUMBER_OF(debug_classes))
            {
                Level = strtoul(opt, &pend, 0);
                if (pend != p)
                {
                    KdbpPrint("filter: bad class name '%.*s'\n", p - opt, opt);
                    continue;
                }
                if (*p == '+')
                    set |= Level;
                else
                    clear |= Level;
            }
        }
        else
        {
            if (*p == '-')
                clear = MAXULONG;
            else
                set = MAXULONG;
        }
        if (*p == '+' || *p == '-')
            p++;

        if (!KdbpGetComponentId(p, &ComponentId))
        {
            KdbpPrint("filter: '%s' is not a valid component name!\n", p);
            return TRUE;
        }

        /* Get current mask value */
        NtSetDebugFilterState(ComponentId, set, TRUE);
        NtSetDebugFilterState(ComponentId, clear, FALSE);
    }

    return TRUE;
}

#ifdef _M_IX86
static PKTSS
KdbpRetrieveTss(
    IN USHORT TssSelector,
    OUT PULONG pType OPTIONAL,
    IN PKDESCRIPTOR pGdtr OPTIONAL)
{
    KDESCRIPTOR Gdtr;
    KGDTENTRY Desc;
    PKTSS Tss;

    /* Retrieve the Global Descriptor Table (user-provided or system) */
    if (pGdtr)
        Gdtr = *pGdtr;
    else
        Ke386GetGlobalDescriptorTable(&Gdtr.Limit);

    /* Check limits */
    if ((TssSelector & (sizeof(KGDTENTRY) - 1)) ||
        (TssSelector < sizeof(KGDTENTRY)) ||
        (TssSelector + sizeof(KGDTENTRY) - 1 > Gdtr.Limit))
    {
        return NULL;
    }

    /* Retrieve the descriptor */
    if (!NT_SUCCESS(KdbpSafeReadMemory(&Desc,
                                       (PVOID)(Gdtr.Base + TssSelector),
                                       sizeof(KGDTENTRY))))
    {
        return NULL;
    }

    /* Check for TSS32(Avl) or TSS32(Busy) */
    if (Desc.HighWord.Bits.Type != 9 && Desc.HighWord.Bits.Type != 11)
    {
        return NULL;
    }
    if (pType) *pType = Desc.HighWord.Bits.Type;

    Tss = (PKTSS)(ULONG_PTR)(Desc.BaseLow |
                             Desc.HighWord.Bytes.BaseMid << 16 |
                             Desc.HighWord.Bytes.BaseHi << 24);

    return Tss;
}

FORCEINLINE BOOLEAN
KdbpIsNestedTss(
    IN USHORT TssSelector,
    IN PKTSS Tss)
{
    USHORT Backlink;

    if (!Tss)
        return FALSE;

    /* Retrieve the TSS Backlink */
    if (!NT_SUCCESS(KdbpSafeReadMemory(&Backlink,
                                       (PVOID)&Tss->Backlink,
                                       sizeof(USHORT))))
    {
        return FALSE;
    }

    return (Backlink != 0 && Backlink != TssSelector);
}

static BOOLEAN
KdbpContextFromPrevTss(
    IN OUT PCONTEXT Context,
    OUT PUSHORT TssSelector,
    IN OUT PKTSS* pTss,
    IN PKDESCRIPTOR pGdtr)
{
    ULONG_PTR Eip, Ebp;
    USHORT Backlink;
    PKTSS Tss = *pTss;

    /* Retrieve the TSS Backlink */
    if (!NT_SUCCESS(KdbpSafeReadMemory(&Backlink,
                                       (PVOID)&Tss->Backlink,
                                       sizeof(USHORT))))
    {
        return FALSE;
    }

    /* Retrieve the parent TSS */
    Tss = KdbpRetrieveTss(Backlink, NULL, pGdtr);
    if (!Tss)
        return FALSE;

    if (!NT_SUCCESS(KdbpSafeReadMemory(&Eip,
                                       (PVOID)&Tss->Eip,
                                       sizeof(ULONG_PTR))))
    {
        return FALSE;
    }

    if (!NT_SUCCESS(KdbpSafeReadMemory(&Ebp,
                                       (PVOID)&Tss->Ebp,
                                       sizeof(ULONG_PTR))))
    {
        return FALSE;
    }

    /* Return the parent TSS and its trap frame */
    *TssSelector = Backlink;
    *pTss = Tss;
    Context->Eip = Eip;
    Context->Ebp = Ebp;
    return TRUE;
}
#endif // _M_IX86

#ifdef _M_AMD64
static
BOOLEAN
GetNextFrame(
    _Inout_ PCONTEXT Context)
{
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG64 ImageBase, EstablisherFrame;
    PVOID HandlerData;

    _SEH2_TRY
    {
        /* Lookup the FunctionEntry for the current RIP */
        FunctionEntry = RtlLookupFunctionEntry(Context->Rip, &ImageBase, NULL);
        if (FunctionEntry == NULL)
        {
            /* No function entry, so this must be a leaf function. Pop the return address from the stack.
            Note: this can happen after the first frame as the result of an exception */
            Context->Rip = *(DWORD64*)Context->Rsp;
            Context->Rsp += sizeof(DWORD64);
            return TRUE;
        }
        else
        {
            RtlVirtualUnwind(UNW_FLAG_NHANDLER,
                             ImageBase,
                             Context->Rip,
                             FunctionEntry,
                             Context,
                             &HandlerData,
                             &EstablisherFrame,
                             NULL);
        }
    }
    _SEH2_EXCEPT(1)
    {
        return FALSE;
    }
    _SEH2_END

    return TRUE;
}
#endif // _M_AMD64

/*!\brief Continues execution of the system/leaves KDB.
 */
static BOOLEAN
KdbpCmdContinue(
    ULONG Argc,
    PCHAR Argv[])
{
    /* Exit the main loop */
    return FALSE;
}

/*!\brief Continues execution of the system/leaves KDB.
 */
static BOOLEAN
KdbpCmdStep(
    ULONG Argc,
    PCHAR Argv[])
{
    ULONG Count = 1;

    if (Argc > 1)
    {
        Count = strtoul(Argv[1], NULL, 0);
        if (Count == 0)
        {
            KdbpPrint("%s: Integer argument required\n", Argv[0]);
            return TRUE;
        }
    }

    if (Argv[0][0] == 'n')
        KdbSingleStepOver = TRUE;
    else
        KdbSingleStepOver = FALSE;

    /* Set the number of single steps and return to the interrupted code. */
    KdbNumSingleSteps = Count;

    return FALSE;
}

/*!\brief Lists breakpoints.
 */
static BOOLEAN
KdbpCmdBreakPointList(
    ULONG Argc,
    PCHAR Argv[])
{
    LONG l;
    ULONG_PTR Address = 0;
    KDB_BREAKPOINT_TYPE Type = 0;
    KDB_ACCESS_TYPE AccessType = 0;
    UCHAR Size = 0;
    UCHAR DebugReg = 0;
    BOOLEAN Enabled = FALSE;
    BOOLEAN Global = FALSE;
    PEPROCESS Process = NULL;
    PCHAR str1, str2, ConditionExpr, GlobalOrLocal;
    CHAR Buffer[20];

    l = KdbpGetNextBreakPointNr(0);
    if (l < 0)
    {
        KdbpPrint("No breakpoints.\n");
        return TRUE;
    }

    KdbpPrint("Breakpoints:\n");
    do
    {
        if (!KdbpGetBreakPointInfo(l, &Address, &Type, &Size, &AccessType, &DebugReg,
                                   &Enabled, &Global, &Process, &ConditionExpr))
        {
            continue;
        }

        if (l == KdbLastBreakPointNr)
        {
            str1 = "\x1b[1m*";
            str2 = "\x1b[0m";
        }
        else
        {
            str1 = " ";
            str2 = "";
        }

        if (Global)
        {
            GlobalOrLocal = "  global";
        }
        else
        {
            GlobalOrLocal = Buffer;
            sprintf(Buffer, "  PID 0x%Ix",
                    (ULONG_PTR)(Process ? Process->UniqueProcessId : INVALID_HANDLE_VALUE));
        }

        if (Type == KdbBreakPointSoftware || Type == KdbBreakPointTemporary)
        {
            KdbpPrint(" %s%03d  BPX  0x%08x%s%s%s%s%s\n",
                      str1, l, Address,
                      Enabled ? "" : "  disabled",
                      GlobalOrLocal,
                      ConditionExpr ? "  IF " : "",
                      ConditionExpr ? ConditionExpr : "",
                      str2);
        }
        else if (Type == KdbBreakPointHardware)
        {
            if (!Enabled)
            {
                KdbpPrint(" %s%03d  BPM  0x%08x  %-5s %-5s  disabled%s%s%s%s\n", str1, l, Address,
                          KDB_ACCESS_TYPE_TO_STRING(AccessType),
                          Size == 1 ? "byte" : (Size == 2 ? "word" : "dword"),
                          GlobalOrLocal,
                          ConditionExpr ? "  IF " : "",
                          ConditionExpr ? ConditionExpr : "",
                          str2);
            }
            else
            {
                KdbpPrint(" %s%03d  BPM  0x%08x  %-5s %-5s  DR%d%s%s%s%s\n", str1, l, Address,
                          KDB_ACCESS_TYPE_TO_STRING(AccessType),
                          Size == 1 ? "byte" : (Size == 2 ? "word" : "dword"),
                          DebugReg,
                          GlobalOrLocal,
                          ConditionExpr ? "  IF " : "",
                          ConditionExpr ? ConditionExpr : "",
                          str2);
            }
        }
    }
    while ((l = KdbpGetNextBreakPointNr(l+1)) >= 0);

    return TRUE;
}

/*!\brief Enables, disables or clears a breakpoint.
 */
static BOOLEAN
KdbpCmdEnableDisableClearBreakPoint(
    ULONG Argc,
    PCHAR Argv[])
{
    PCHAR pend;
    ULONG BreakPointNr;

    if (Argc < 2)
    {
        KdbpPrint("%s: argument required\n", Argv[0]);
        return TRUE;
    }

    pend = Argv[1];
    BreakPointNr = strtoul(Argv[1], &pend, 0);
    if (pend == Argv[1] || *pend != '\0')
    {
        KdbpPrint("%s: integer argument required\n", Argv[0]);
        return TRUE;
    }

    if (Argv[0][1] == 'e') /* enable */
    {
        KdbpEnableBreakPoint(BreakPointNr, NULL);
    }
    else if (Argv [0][1] == 'd') /* disable */
    {
        KdbpDisableBreakPoint(BreakPointNr, NULL);
    }
    else /* clear */
    {
        ASSERT(Argv[0][1] == 'c');
        KdbpDeleteBreakPoint(BreakPointNr, NULL);
    }

    return TRUE;
}

/*!\brief Sets a software or hardware (memory) breakpoint at the given address.
 */
static BOOLEAN
KdbpCmdBreakPoint(ULONG Argc, PCHAR Argv[])
{
    ULONGLONG Result = 0;
    ULONG_PTR Address;
    KDB_BREAKPOINT_TYPE Type;
    UCHAR Size = 0;
    KDB_ACCESS_TYPE AccessType = 0;
    ULONG AddressArgIndex, i;
    LONG ConditionArgIndex;
    BOOLEAN Global = TRUE;

    if (Argv[0][2] == 'x') /* software breakpoint */
    {
        if (Argc < 2)
        {
            KdbpPrint("bpx: Address argument required.\n");
            return TRUE;
        }

        AddressArgIndex = 1;
        Type = KdbBreakPointSoftware;
    }
    else /* memory breakpoint */
    {
        ASSERT(Argv[0][2] == 'm');

        if (Argc < 2)
        {
            KdbpPrint("bpm: Access type argument required (one of r, w, rw, x)\n");
            return TRUE;
        }

        if (_stricmp(Argv[1], "x") == 0)
            AccessType = KdbAccessExec;
        else if (_stricmp(Argv[1], "r") == 0)
            AccessType = KdbAccessRead;
        else if (_stricmp(Argv[1], "w") == 0)
            AccessType = KdbAccessWrite;
        else if (_stricmp(Argv[1], "rw") == 0)
            AccessType = KdbAccessReadWrite;
        else
        {
            KdbpPrint("bpm: Unknown access type '%s'\n", Argv[1]);
            return TRUE;
        }

        if (Argc < 3)
        {
            KdbpPrint("bpm: %s argument required.\n", AccessType == KdbAccessExec ? "Address" : "Memory size");
            return TRUE;
        }

        AddressArgIndex = 3;
        if (_stricmp(Argv[2], "byte") == 0)
            Size = 1;
        else if (_stricmp(Argv[2], "word") == 0)
            Size = 2;
        else if (_stricmp(Argv[2], "dword") == 0)
            Size = 4;
        else if (AccessType == KdbAccessExec)
        {
            Size = 1;
            AddressArgIndex--;
        }
        else
        {
            KdbpPrint("bpm: Unknown memory size '%s'\n", Argv[2]);
            return TRUE;
        }

        if (Argc <= AddressArgIndex)
        {
            KdbpPrint("bpm: Address argument required.\n");
            return TRUE;
        }

        Type = KdbBreakPointHardware;
    }

    /* Put the arguments back together */
    ConditionArgIndex = -1;
    for (i = AddressArgIndex; i < (Argc-1); i++)
    {
        if (strcmp(Argv[i+1], "IF") == 0) /* IF found */
        {
            ConditionArgIndex = i + 2;
            if ((ULONG)ConditionArgIndex >= Argc)
            {
                KdbpPrint("%s: IF requires condition expression.\n", Argv[0]);
                return TRUE;
            }

            for (i = ConditionArgIndex; i < (Argc-1); i++)
                Argv[i][strlen(Argv[i])] = ' ';

            break;
        }

        Argv[i][strlen(Argv[i])] = ' ';
    }

    /* Evaluate the address expression */
    if (!KdbpEvaluateExpression(Argv[AddressArgIndex],
                                Argv[AddressArgIndex] - Argv[0],
                                &Result))
    {
        return TRUE;
    }

    if (Result > (ULONGLONG)(~((ULONG_PTR)0)))
        KdbpPrint("%s: Warning: Address %I64x is beeing truncated\n", Argv[0],Result);

    Address = (ULONG_PTR)Result;

    KdbpInsertBreakPoint(Address, Type, Size, AccessType,
                         (ConditionArgIndex < 0) ? NULL : Argv[ConditionArgIndex],
                         Global, NULL);

    return TRUE;
}

/*!\brief Bugchecks the system.
 */
static BOOLEAN
KdbpCmdBugCheck(
    ULONG Argc,
    PCHAR Argv[])
{
    /* Set the flag and quit looping */
    KdbpBugCheckRequested = TRUE;
    return FALSE;
}

static BOOLEAN
KdbpCmdReboot(
    ULONG Argc,
    PCHAR Argv[])
{
    /* Reboot immediately (we do not return) */
    HalReturnToFirmware(HalRebootRoutine);
    return FALSE;
}

/*!\brief Display debug messages on screen, with paging.
 *
 * Keys for per-page view: Home, End, PageUp, Arrow Up, PageDown,
 * all others are as PageDown.
 */
static BOOLEAN
KdbpCmdDmesg(
    ULONG Argc,
    PCHAR Argv[])
{
    ULONG beg, end;

    KdbpIsInDmesgMode = TRUE; /* Toggle logging flag */
    if (!KdpDmesgBuffer)
    {
        KdbpPrint("Dmesg: error, buffer is not allocated! /DEBUGPORT=SCREEN kernel param required for dmesg.\n");
        return TRUE;
    }

    KdbpPrint("*** Dmesg *** TotalWritten=%lu, BufferSize=%lu, CurrentPosition=%lu\n",
              KdbDmesgTotalWritten, KdpDmesgBufferSize, KdpDmesgCurrentPosition);

    /* Pass data to the pager */
    end = KdpDmesgCurrentPosition;
    beg = (end + KdpDmesgFreeBytes) % KdpDmesgBufferSize;

    /* No roll-overs, and overwritten=lost bytes */
    if (KdbDmesgTotalWritten <= KdpDmesgBufferSize)
    {
        /* Show buffer (KdpDmesgBuffer + beg, num) */
        KdbpPrint(KdpDmesgBuffer, KdpDmesgCurrentPosition);
    }
    else
    {
        /* Show 2 buffers: (KdpDmesgBuffer + beg, KdpDmesgBufferSize - beg)
         *            and: (KdpDmesgBuffer,       end) */
        KdbpPrint(KdpDmesgBuffer + beg, KdpDmesgBufferSize - beg);
        KdbpPrint("*** Dmesg: buffer rollup ***\n");
        KdbpPrint(KdpDmesgBuffer,       end);
    }
    KdbpPrint("*** Dmesg: end of output ***\n");

    KdbpIsInDmesgMode = FALSE; /* Toggle logging flag */

    return TRUE;
}

/*!\brief Sets or displays a config variables value.
 */
static BOOLEAN
KdbpCmdSet(
    ULONG Argc,
    PCHAR Argv[])
{
    LONG l;
    BOOLEAN First;
    PCHAR pend = 0;
    KDB_ENTER_CONDITION ConditionFirst = KdbDoNotEnter;
    KDB_ENTER_CONDITION ConditionLast = KdbDoNotEnter;

    static const PCHAR ExceptionNames[21] =
    {
        "ZERODEVIDE", "DEBUGTRAP", "NMI", "INT3", "OVERFLOW", "BOUND", "INVALIDOP",
        "NOMATHCOP", "DOUBLEFAULT", "RESERVED(9)", "INVALIDTSS", "SEGMENTNOTPRESENT",
        "STACKFAULT", "GPF", "PAGEFAULT", "RESERVED(15)", "MATHFAULT", "ALIGNMENTCHECK",
        "MACHINECHECK", "SIMDFAULT", "OTHERS"
    };

    if (Argc == 1)
    {
        KdbpPrint("Available settings:\n");
        KdbpPrint("  syntax [intel|at&t]\n");
        KdbpPrint("  condition [exception|*] [first|last] [never|always|kmode|umode]\n");
        KdbpPrint("  break_on_module_load [true|false]\n");
    }
    else if (strcmp(Argv[1], "syntax") == 0)
    {
        if (Argc == 2)
        {
            KdbpPrint("syntax = %s\n", KdbUseIntelSyntax ? "intel" : "at&t");
        }
        else if (Argc >= 3)
        {
            if (_stricmp(Argv[2], "intel") == 0)
                KdbUseIntelSyntax = TRUE;
            else if (_stricmp(Argv[2], "at&t") == 0)
                KdbUseIntelSyntax = FALSE;
            else
                KdbpPrint("Unknown syntax '%s'.\n", Argv[2]);
        }
    }
    else if (strcmp(Argv[1], "condition") == 0)
    {
        if (Argc == 2)
        {
            KdbpPrint("Conditions:                 (First)  (Last)\n");
            for (l = 0; l < RTL_NUMBER_OF(ExceptionNames) - 1; l++)
            {
                if (!ExceptionNames[l])
                    continue;

                if (!KdbpGetEnterCondition(l, TRUE, &ConditionFirst))
                    ASSERT(FALSE);

                if (!KdbpGetEnterCondition(l, FALSE, &ConditionLast))
                    ASSERT(FALSE);

                KdbpPrint("  #%02d  %-20s %-8s %-8s\n", l, ExceptionNames[l],
                          KDB_ENTER_CONDITION_TO_STRING(ConditionFirst),
                          KDB_ENTER_CONDITION_TO_STRING(ConditionLast));
            }

            ASSERT(l == (RTL_NUMBER_OF(ExceptionNames) - 1));
            KdbpPrint("       %-20s %-8s %-8s\n", ExceptionNames[l],
                      KDB_ENTER_CONDITION_TO_STRING(ConditionFirst),
                      KDB_ENTER_CONDITION_TO_STRING(ConditionLast));
        }
        else
        {
            if (Argc >= 5 && strcmp(Argv[2], "*") == 0) /* Allow * only when setting condition */
            {
                l = -1;
            }
            else
            {
                l = strtoul(Argv[2], &pend, 0);

                if (Argv[2] == pend)
                {
                    for (l = 0; l < RTL_NUMBER_OF(ExceptionNames); l++)
                    {
                        if (!ExceptionNames[l])
                            continue;

                        if (_stricmp(ExceptionNames[l], Argv[2]) == 0)
                            break;
                    }
                }

                if (l >= RTL_NUMBER_OF(ExceptionNames))
                {
                    KdbpPrint("Unknown exception '%s'.\n", Argv[2]);
                    return TRUE;
                }
            }

            if (Argc > 4)
            {
                if (_stricmp(Argv[3], "first") == 0)
                    First = TRUE;
                else if (_stricmp(Argv[3], "last") == 0)
                    First = FALSE;
                else
                {
                    KdbpPrint("set condition: second argument must be 'first' or 'last'\n");
                    return TRUE;
                }

                if (_stricmp(Argv[4], "never") == 0)
                    ConditionFirst = KdbDoNotEnter;
                else if (_stricmp(Argv[4], "always") == 0)
                    ConditionFirst = KdbEnterAlways;
                else if (_stricmp(Argv[4], "umode") == 0)
                    ConditionFirst = KdbEnterFromUmode;
                else if (_stricmp(Argv[4], "kmode") == 0)
                    ConditionFirst = KdbEnterFromKmode;
                else
                {
                    KdbpPrint("set condition: third argument must be 'never', 'always', 'umode' or 'kmode'\n");
                    return TRUE;
                }

                if (!KdbpSetEnterCondition(l, First, ConditionFirst))
                {
                    if (l >= 0)
                        KdbpPrint("Couldn't change condition for exception #%02d\n", l);
                    else
                        KdbpPrint("Couldn't change condition for all exceptions\n", l);
                }
            }
            else /* Argc >= 3 */
            {
                if (!KdbpGetEnterCondition(l, TRUE, &ConditionFirst))
                    ASSERT(FALSE);

                if (!KdbpGetEnterCondition(l, FALSE, &ConditionLast))
                    ASSERT(FALSE);

                if (l < (RTL_NUMBER_OF(ExceptionNames) - 1))
                {
                    KdbpPrint("Condition for exception #%02d (%s): FirstChance %s  LastChance %s\n",
                              l, ExceptionNames[l],
                              KDB_ENTER_CONDITION_TO_STRING(ConditionFirst),
                              KDB_ENTER_CONDITION_TO_STRING(ConditionLast));
                }
                else
                {
                    KdbpPrint("Condition for all other exceptions: FirstChance %s  LastChance %s\n",
                              KDB_ENTER_CONDITION_TO_STRING(ConditionFirst),
                              KDB_ENTER_CONDITION_TO_STRING(ConditionLast));
                }
            }
        }
    }
    else if (strcmp(Argv[1], "break_on_module_load") == 0)
    {
        if (Argc == 2)
            KdbpPrint("break_on_module_load = %s\n", KdbBreakOnModuleLoad ? "enabled" : "disabled");
        else if (Argc >= 3)
        {
            if (_stricmp(Argv[2], "enable") == 0 || _stricmp(Argv[2], "enabled") == 0 || _stricmp(Argv[2], "true") == 0)
                KdbBreakOnModuleLoad = TRUE;
            else if (_stricmp(Argv[2], "disable") == 0 || _stricmp(Argv[2], "disabled") == 0 || _stricmp(Argv[2], "false") == 0)
                KdbBreakOnModuleLoad = FALSE;
            else
                KdbpPrint("Unknown setting '%s'.\n", Argv[2]);
        }
    }
    else
    {
        KdbpPrint("Unknown setting '%s'.\n", Argv[1]);
    }

    return TRUE;
}

/*!\brief Displays help screen.
 */
static BOOLEAN
KdbpCmdHelp(
    ULONG Argc,
    PCHAR Argv[])
{
    ULONG i;

    KdbpPrint("Kernel debugger commands:\n");
    for (i = 0; i < RTL_NUMBER_OF(KdbDebuggerCommands); i++)
    {
        if (!KdbDebuggerCommands[i].Syntax) /* Command group */
        {
            if (i > 0)
                KdbpPrint("\n");

            KdbpPrint("\x1b[7m* %s:\x1b[0m\n", KdbDebuggerCommands[i].Help);
            continue;
        }

        KdbpPrint("  %-20s - %s\n",
                  KdbDebuggerCommands[i].Syntax,
                  KdbDebuggerCommands[i].Help);
    }

    KdbpPrint("\n");
    KdbpPrint("\x1b[7m* %s:\x1b[0m\n", "Misc");
    for (i = 0; i < RTL_NUMBER_OF(KdbCliExtensions); i++)
    {
        if (!KdbCliExtensions[i].Name)
            break;
        KdbpPrint("  %-20s - %s\n",
                  KdbCliExtensions[i].Syntax,
                  KdbCliExtensions[i].Help);
    }

    return TRUE;
}

/*!\brief Prints the given string with printf-like formatting.
 *
 * \param Format  Format of the string/arguments.
 * \param ...     Variable number of arguments matching the format specified in \a Format.
 *
 * \note Doesn't correctly handle \\t and terminal escape sequences when calculating the
 *       number of lines required to print a single line from the Buffer in the terminal.
 *       Prints maximum 4096 chars, because of its buffer size.
 *       Uses KdpDPrintf internally (NOT DbgPrint!). Callers must already hold the debugger lock.
 */
VOID
KdbpPrint(
    IN PCSZ Format,
    IN ...  OPTIONAL)
{
    static CHAR Buffer[4096];
    CHAR c = '\0';
    PCHAR p, p2;
    ULONG Length;
    SIZE_T i, j;
    va_list ap;

    /* Get the string */
    va_start(ap, Format);
    Length = _vsnprintf(Buffer, sizeof(Buffer) - 1, Format, ap);
    Buffer[Length] = '\0';
    va_end(ap);

    p = Buffer;
    while (p[0] != '\0')
    {
        i = strcspn(p, "\n");

        /* Insert a NUL after the line and print only the current line. */
        if (p[i] == '\n' && p[i + 1] != '\0')
        {
            c = p[i + 1];
            p[i + 1] = '\0';
        }
        else
        {
            c = '\0';
        }

        /* Remove escape sequences from the line */
        while ((p2 = strrchr(p, '\x1b'))) /* Look for escape character */
        {
            size_t len = strlen(p2);
            if (p2[1] == '[')
            {
                j = 2;
                while (!isalpha(p2[j++]));
                memmove(p2, p2 + j, len + 1 - j);
            }
            else
            {
                memmove(p2, p2 + 1, len);
            }
        }

        KdpDprintf("%s", p);

        if (c != '\0')
            p[i + 1] = c;

        /* Set p to the start of the next line */
        p += i;
        if (p[0] == '\n')
        {
            p++;
        }
        else
        {
            ASSERT(p[0] == '\0');
        }
    }
}

VOID
KdbpPrintUnicodeString(
    _In_ PCUNICODE_STRING String)
{
    ULONG i;

    if ((String == NULL) || (String->Buffer == NULL))
    {
        KdbpPrint("<NULL>");
        return;
    }

    for (i = 0; i < String->Length / sizeof(WCHAR); i++)
    {
        KdbpPrint("%c", (CHAR)String->Buffer[i]);
    }
}

/** memrchr(), explicitly defined, since was absent in MinGW of RosBE. */
/*
 * Reverse memchr()
 * Find the last occurrence of 'c' in the buffer 's' of size 'n'.
 */
void *
memrchr(const void *s, int c, size_t n)
{
    const unsigned char *cp;

    if (n != 0)
    {
        cp = (unsigned char *)s + n;
        do
        {
            if (*(--cp) == (unsigned char)c)
                return (void *)cp;
        } while (--n != 0);
    }
    return NULL;
}

/*!\brief Reads a line of user-input.
 *
 * \param Buffer  Buffer to store the input into. Trailing newlines are removed.
 * \param Size    Size of \a Buffer.
 *
 * \note Accepts only \n newlines, \r is ignored.
 */
static VOID
KdbpReadCommand(
    OUT PCHAR Buffer,
    IN  ULONG Size)
{
    STRING Data;
    ULONG DataLength;

    Data.Buffer = Buffer;
    Data.Length = 0;
    Data.MaximumLength = Size - 1;
    KdReceivePacket(PACKET_TYPE_KD_DEBUG_IO, NULL, &Data, &DataLength, NULL);
    Buffer[DataLength] = '\0';
}

static
ULONG_PTR NTAPI
KdbpApiGetExpression(
    _In_ PCSTR lpExpression)
{
    BOOLEAN Ok;
    ULONGLONG Result;

    Ok = KdbpEvaluateExpression(lpExpression, strlen(lpExpression), &Result);
    if (!Ok)
        return 0;
    return Result;
}

static
VOID NTAPI
KdbpApiGetSymbol(
    _In_ PVOID Offset,
    _Out_ PCHAR pchBuffer,
    _Out_ ULONG_PTR* pDisplacement)
{
    KdbSymPrintAddress((PVOID)Offset, NULL);
}

static
ULONG NTAPI
KdbpApiDisasm(
    _Inout_ ULONG_PTR* lpOffset,
    _In_ PCSTR lpBuffer,
    _In_ ULONG fShowEffectiveAddress)
{
    LONG InstLen;

    InstLen = KdbpDisassemble(*lpOffset, KdbUseIntelSyntax);
    if (InstLen < 0)
        return FALSE;

    *lpOffset += InstLen;
    return TRUE;
}

static
ULONG NTAPI
KdbpApiReadProcessMemory(
    _In_ ULONG_PTR Offset,
    _Out_ PVOID lpBuffer,
    _In_ ULONG cb,
    _Out_ PULONG lpcbBytesRead)
{
    if (!NT_SUCCESS(KdbpSafeReadMemory(lpBuffer, (PVOID)Offset, cb)))
        return FALSE;
    *lpcbBytesRead = cb;
    return TRUE;
}

static
ULONG NTAPI
KdbpApiGetThreadContext(
    _In_ ULONG Processor,
    _Out_ PCONTEXT lpContext,
    _In_ ULONG cbSizeOfContext)
{
    if (cbSizeOfContext != sizeof(CONTEXT))
        return FALSE;
    RtlCopyMemory(lpContext, KdbCurrentContext, sizeof(CONTEXT));
    return TRUE;
}

static
ULONG NTAPI
KdbpApiSetThreadContext(
    _In_ ULONG Processor,
    _In_ PCONTEXT lpContext,
    _In_ ULONG cbSizeOfContext)
{
    if (cbSizeOfContext != sizeof(CONTEXT))
        return FALSE;
    RtlCopyMemory(KdbCurrentContext, lpContext, sizeof(CONTEXT));

    /* FIXME:
     * KeUnstackDetachProcess(...);
     * KeStackAttachProcess(...);
     */

    return TRUE;
}

static
ULONG NTAPI
KdbpApiIoctl(
    _In_ USHORT IoctlType,
    _Inout_ PVOID lpvData,
    _In_ ULONG cbSize)
{
    switch (IoctlType)
    {
    case IG_GET_DEBUGGER_DATA:
    {
        RtlCopyMemory(lpvData, &KdDebuggerDataBlock, sizeof(KdDebuggerDataBlock));
        return TRUE;
    }
    case IG_DUMP_SYMBOL_INFO:
    {
        PSYM_DUMP_PARAM sdp = lpvData;
        const KDP_KNOWN_FIELD* KnownField;
        PLIST_ENTRY Entry;
        ULONG i, Offset;
        FIELD_INFO Field;
        if (sdp->Options & DBG_DUMP_LIST)
        {
            KnownField = KdbpGetKnownField(sdp->sName + 4, sdp->Fields[0].fName);
            if (!KnownField)
                return FALSE;
            Offset = KnownField->Offset;

            Entry = (PLIST_ENTRY)(ULONG_PTR)sdp->addr;
            if (!(sdp->Options & DBG_DUMP_ADDRESS_OF_FIELD))
                Entry = (PLIST_ENTRY)((ULONG_PTR)Entry + Offset);
            while ((ULONG_PTR)Entry->Flink != sdp->addr)
            {
                Field.address = (ULONG_PTR)Entry - Offset;
                if (sdp->CallbackRoutine(&Field, sdp->Context))
                    break;
                Entry = Entry->Flink;
            }
        }
        else
        {
            for (i = 0; i < sdp->nFields; i++)
            {
                KnownField = KdbpGetKnownField(sdp->sName + 4, sdp->Fields[i].fName);
                if (!KnownField)
                    return FALSE;
                Offset = KnownField->Offset;
                if (sdp->Fields[i].fOptions & DBG_DUMP_FIELD_COPY_FIELD_DATA)
                {
                    sdp->size = KnownField->Size;
                    RtlCopyMemory(sdp->Fields[i].pBuffer, (PVOID)(ULONG_PTR)(sdp->addr + Offset), sdp->size);
                }
                else
                    sdp->Fields[i].address = *(ULONG_PTR*)(ULONG_PTR)(sdp->addr + Offset);
            }
        }
        return TRUE;
    }
    case IG_GET_CURRENT_THREAD:
    {
        PGET_CURRENT_THREAD_ADDRESS gcta = lpvData;
        gcta->Address = (ULONG_PTR)PsGetCurrentThread();
        return TRUE;
    }
    case IG_GET_CURRENT_PROCESS:
    {
        PGET_CURRENT_PROCESS_ADDRESS gcpa = lpvData;
        gcpa->Address = (ULONG_PTR)PsGetCurrentProcess();
        return TRUE;
    }
    case IG_GET_EXPRESSION_EX:
    {
        PGET_EXPRESSION_EX gee = lpvData;
        ULONGLONG Value;
        if (!KdbpEvaluateExpression(gee->Expression, strlen(gee->Expression), &Value))
            return FALSE;
        gee->Value = Value;
        gee->Remainder = strchr(gee->Expression, ' ');
        return TRUE;
    }
    default:
        return FALSE;
    }

    /* Must not get there, as default case already handled unknown types */
    ASSERT(FALSE);
    return FALSE;
}

static
ULONG NTAPI
KdbpApiStackTrace(
    _In_ ULONG_PTR FramePointer,
    _In_ ULONG_PTR StackPointer,
    _In_ ULONG_PTR ProgramCounter,
    _Out_ PEXTSTACKTRACE StackFrames,
    _In_ ULONG Frames)
{
#ifdef _M_AMD64
    ULONG Count = 0;
    CONTEXT Context = *KdbCurrentContext;

    Context.Rsp = StackPointer;
    Context.Rip = ProgramCounter;

    while (Count < Frames)
    {
        BOOLEAN GotNextFrame;

        if (Context.Rip == 0 || Context.Rsp == 0)
            break;

        StackFrames[Count].FramePointer = Context.Rsp;
        StackFrames[Count].ProgramCounter = Context.Rip;
        Count++;

        GotNextFrame = GetNextFrame(&Context);
        if (!GotNextFrame)
            break;
    }

    return Count;

#elif defined(_M_IX86)
    ULONG Count = 0;
    CONTEXT Context = *KdbCurrentContext;
    ULONG_PTR Frame = FramePointer;
    ULONG_PTR Address;
    KDESCRIPTOR Gdtr;
    USHORT TssSelector;
    PKTSS Tss;

    /* Retrieve the Global Descriptor Table */
    Ke386GetGlobalDescriptorTable(&Gdtr.Limit);

    /* Retrieve the current (active) TSS */
    TssSelector = Ke386GetTr();
    Tss = KdbpRetrieveTss(TssSelector, NULL, &Gdtr);

    /* Walk through the frames */
    while (Count < Frames)
    {
        BOOLEAN GotNextFrame;

        if (Frame == 0)
            goto CheckForParentTSS;

        Address = 0;
        if (!NT_SUCCESS(KdbpSafeReadMemory(&Address, (PVOID)(Frame + sizeof(ULONG_PTR)), sizeof(ULONG_PTR))))
        {
            goto CheckForParentTSS;
        }

        if (Address == 0)
            goto CheckForParentTSS;

        GotNextFrame = NT_SUCCESS(KdbpSafeReadMemory(&Frame, (PVOID)Frame, sizeof(ULONG_PTR)));
        if (GotNextFrame)
        {
            KeSetContextFrameRegister(&Context, Frame);
        }

        StackFrames[Count].FramePointer = Frame;
        StackFrames[Count].ProgramCounter = Address;
        Count++;

        if (!GotNextFrame)
            goto CheckForParentTSS;

        continue;

CheckForParentTSS:
        /*
         * We have ended the stack walking for the current (active) TSS.
         * Check whether this TSS was nested, and if so switch to its parent
         * and walk its stack.
         */
        if (!KdbpIsNestedTss(TssSelector, Tss))
            break; // The TSS is not nested, we stop there.

        GotNextFrame = KdbpContextFromPrevTss(&Context, &TssSelector, &Tss, &Gdtr);
        if (!GotNextFrame)
            break; // Cannot retrieve the parent TSS, we stop there.

        Address = Context.Eip;
        Frame = Context.Ebp;

        StackFrames[Count].FramePointer = Frame;
        StackFrames[Count].ProgramCounter = Address;
        Count++;
    }

    return Count;
#else
    return 0;
#endif
}

WINDBG_EXTENSION_APIS ExtensionApis = {
    KdbpPrint,
    KdbpApiGetExpression,
    KdbpApiGetSymbol,
    KdbpApiDisasm,
    KdbpApiReadProcessMemory,
    KdbpApiGetThreadContext,
    KdbpApiSetThreadContext,
    KdbpApiIoctl,
    KdbpApiStackTrace,
};

BOOLEAN
NTAPI
KdbRegisterCliExtension(
    PVOID arg)
{
    PKDBG_CLI_REGISTRATION Registration = arg;
    PKDBG_EXTENSION_API p;
    ULONG i = 0;

    /* Copy all APIs to our local array */
    for (p = Registration->Api; p->Name; p++)
    {
        for (i = 0; i < ARRAYSIZE(KdbCliExtensions); i++)
        {
            if (!KdbCliExtensions[i].Name || strcmp(KdbCliExtensions[i].Name, p->Name) == 0)
                break;
        }
        if (i >= ARRAYSIZE(KdbCliExtensions))
            return FALSE;
        if (!KdbCliExtensions[i].Name)
            DPRINT1("Registering new function '%s'\n", p->Name);
        KdbCliExtensions[i] = *p;
    }

    /* Call init function */
    Registration->InitRoutine(&ExtensionApis, 0, 0);

    return TRUE;
}

static
BOOLEAN
KdbpInvokeCliExtension(
    IN PCHAR Name,
    IN PCSTR Args)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(KdbCliExtensions); i++)
    {
        if (!KdbCliExtensions[i].Name)
            break;

        if (strcmp(KdbCliExtensions[i].Name, Name) == 0)
        {
            KdbCliExtensions[i].Routine(NULL, NULL, 0, 0, Args);
            return TRUE;
        }
    }

    return FALSE;
}

/*!\brief Parses command line and executes command if found
 *
 * \param Command    Command line to parse and execute if possible.
 *
 * \retval TRUE   Don't continue execution.
 * \retval FALSE  Continue execution (leave KDB)
 */
static BOOLEAN
KdbpDoCommand(
    IN PCHAR Command)
{
    SIZE_T i;
    PCHAR p;
    ULONG Argc;
    PCSZ AllArguments;
    // FIXME: for what do we need a 1024 characters command line and 256 tokens?
    static PCHAR Argv[256];
    static CHAR OrigCommand[1024];

    RtlStringCbCopyA(OrigCommand, sizeof(OrigCommand), Command);

    Argc = 0;
    p = Command;

    for (;;)
    {
        while (*p == '\t' || *p == ' ')
            p++;

        if (*p == '\0')
            break;

        i = strcspn(p, "\t ");
        Argv[Argc++] = p;
        p += i;
        if (*p == '\0')
            break;

        *p = '\0';
        p++;
    }

    if (Argc < 1)
        return TRUE;

    for (i = 0; i < RTL_NUMBER_OF(KdbDebuggerCommands); i++)
    {
        if (!KdbDebuggerCommands[i].Name)
            continue;

        if (strcmp(KdbDebuggerCommands[i].Name, Argv[0]) == 0)
        {
            return KdbDebuggerCommands[i].Fn(Argc, Argv);
        }
    }

    AllArguments = OrigCommand + strlen(Argv[0]);
    if (AllArguments[0] == ' ')
        AllArguments++;

    if (KdbpInvokeCliExtension(Argv[0], AllArguments))
    {
        return TRUE;
    }

    KdbpPrint("Command '%s' is unknown.\n", OrigCommand);
    return TRUE;
}

/*!\brief KDB Main Loop.
 *
 * \param EnteredOnSingleStep  TRUE if KDB was entered on single step.
 */
VOID
KdbpCliMainLoop(
    IN BOOLEAN EnteredOnSingleStep)
{
    static CHAR Command[1024];
    BOOLEAN Continue;

    if (EnteredOnSingleStep)
    {
        if (!KdbSymPrintAddress((PVOID)KeGetContextPc(KdbCurrentContext), KdbCurrentContext))
        {
            KdbpPrint("<%p>", KeGetContextPc(KdbCurrentContext));
        }

        KdbpPrint(": ");
        if (KdbpDisassemble(KeGetContextPc(KdbCurrentContext), KdbUseIntelSyntax) < 0)
        {
            KdbpPrint("<INVALID>");
        }
        KdbpPrint("\n");
    }

    /* Main loop */
    do
    {
        /* Read a command and remember it */
        KdbpReadCommand(Command, sizeof(Command));

        /* Call the command */
        Continue = KdbpDoCommand(Command);
    }
    while (Continue);
}

/*!\brief This function is called by KdbEnterDebuggerException...
 *
 * Used to interpret the init file in a context with a trapframe setup
 * (KdbpCliInit call KdbEnter which will call KdbEnterDebuggerException which will
 * call this function if KdbInitFileBuffer is not NULL.
 */
VOID
KdbpCliInterpretInitFile(VOID)
{
    PCHAR p1, p2;
    INT_PTR i;
    CHAR c;

    /* Execute the commands in the init file */
    DPRINT("KDB: Executing KDBinit file...\n");
    p1 = KdbInitFileBuffer;
    while (p1[0] != '\0')
    {
        i = strcspn(p1, "\r\n");
        if (i > 0)
        {
            c = p1[i];
            p1[i] = '\0';

            /* Look for "break" command and comments */
            p2 = p1;

            while (isspace(p2[0]))
                p2++;

            if (strncmp(p2, "break", sizeof("break")-1) == 0 &&
                (p2[sizeof("break")-1] == '\0' || isspace(p2[sizeof("break")-1])))
            {
                /* break into the debugger */
                KdbpCliMainLoop(FALSE);
            }
            else if (p2[0] != '#' && p2[0] != '\0') /* Ignore empty lines and comments */
            {
                KdbpDoCommand(p1);
            }

            p1[i] = c;
        }

        p1 += i;
        while (p1[0] == '\r' || p1[0] == '\n')
            p1++;
    }
    DPRINT("KDB: KDBinit executed\n");
}

/*!\brief Called when KDB is initialized
 *
 * Reads the KDBinit file from the SystemRoot\System32\drivers\etc directory and executes it.
 */
VOID
KdbpCliInit(VOID)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING FileName;
    IO_STATUS_BLOCK Iosb;
    FILE_STANDARD_INFORMATION FileStdInfo;
    HANDLE hFile = NULL;
    INT FileSize;
    PCHAR FileBuffer;
    ULONG OldEflags;

    /* Initialize the object attributes */
    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\System32\\drivers\\etc\\KDBinit");
    InitializeObjectAttributes(&ObjectAttributes,
                               &FileName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    /* Open the file */
    Status = ZwOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE,
                        &ObjectAttributes, &Iosb, 0,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
                        FILE_NO_INTERMEDIATE_BUFFERING);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("Could not open \\SystemRoot\\System32\\drivers\\etc\\KDBinit (Status 0x%x)", Status);
        return;
    }

    /* Get the size of the file */
    Status = ZwQueryInformationFile(hFile, &Iosb, &FileStdInfo, sizeof(FileStdInfo),
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(hFile);
        DPRINT("Could not query size of \\SystemRoot\\System32\\drivers\\etc\\KDBinit (Status 0x%x)", Status);
        return;
    }
    FileSize = FileStdInfo.EndOfFile.u.LowPart;

    /* Allocate memory for the file */
    FileBuffer = ExAllocatePool(PagedPool, FileSize + 1); /* add 1 byte for terminating '\0' */
    if (!FileBuffer)
    {
        ZwClose(hFile);
        DPRINT("Could not allocate %d bytes for KDBinit file\n", FileSize);
        return;
    }

    /* Load file into memory */
    Status = ZwReadFile(hFile, NULL, NULL, NULL, &Iosb, FileBuffer, FileSize, NULL, NULL);
    ZwClose(hFile);

    if (!NT_SUCCESS(Status) && Status != STATUS_END_OF_FILE)
    {
        ExFreePool(FileBuffer);
        DPRINT("Could not read KDBinit file into memory (Status 0x%lx)\n", Status);
        return;
    }

    FileSize = min(FileSize, (INT)Iosb.Information);
    FileBuffer[FileSize] = '\0';

    /* Enter critical section */
    OldEflags = __readeflags();
    _disable();

    /* Interpret the init file... */
    KdbInitFileBuffer = FileBuffer;
    //KdbEnter(); // FIXME
    KdbInitFileBuffer = NULL;

    /* Leave critical section */
    __writeeflags(OldEflags);

    ExFreePool(FileBuffer);
}
