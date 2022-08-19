#ifndef _WDBGEXTS_
#define _WDBGEXTS_

enum
{
    DBGKD_SIMULATION_NONE,
    DBGKD_SIMULATION_EXDI
};

#define KD_SECONDARY_VERSION_DEFAULT                    0
#define KD_SECONDARY_VERSION_AMD64_OBSOLETE_CONTEXT_1   0
#define KD_SECONDARY_VERSION_AMD64_OBSOLETE_CONTEXT_2   1
#define KD_SECONDARY_VERSION_AMD64_CONTEXT              2

#if defined(_AMD64_)
#define CURRENT_KD_SECONDARY_VERSION                    KD_SECONDARY_VERSION_AMD64_CONTEXT
#else
#define CURRENT_KD_SECONDARY_VERSION                    KD_SECONDARY_VERSION_DEFAULT
#endif

#define DBGKD_VERS_FLAG_MP                              0x0001
#define DBGKD_VERS_FLAG_DATA                            0x0002
#define DBGKD_VERS_FLAG_PTR64                           0x0004
#define DBGKD_VERS_FLAG_NOMM                            0x0008
#define DBGKD_VERS_FLAG_HSS                             0x0010
#define DBGKD_VERS_FLAG_PARTITIONS                      0x0020

#define KDBG_TAG                                        'GBDK'

typedef enum _DBGKD_MAJOR_TYPES
{
    DBGKD_MAJOR_NT,
    DBGKD_MAJOR_XBOX,
    DBGKD_MAJOR_BIG,
    DBGKD_MAJOR_EXDI,
    DBGKD_MAJOR_NTBD,
    DBGKD_MAJOR_EFI,
    DBGKD_MAJOR_TNT,
    DBGKD_MAJOR_SINGULARITY,
    DBGKD_MAJOR_HYPERVISOR,
    DBGKD_MAJOR_MIDORI,
    DBGKD_MAJOR_COUNT
} DBGKD_MAJOR_TYPES;

//
// The major type is in the high byte
//
#define DBGKD_MAJOR_TYPE(MajorVersion) \
    ((DBGKD_MAJOR_TYPES)((MajorVersion) >> 8))

typedef struct _DBGKD_GET_VERSION32
{
    USHORT MajorVersion;
    USHORT MinorVersion;
    USHORT ProtocolVersion;
    USHORT Flags;
    ULONG KernBase;
    ULONG PsLoadedModuleList;
    USHORT MachineType;
    USHORT ThCallbackStack;
    USHORT NextCallback;
    USHORT FramePointer;
    ULONG KiCallUserMode;
    ULONG KeUserCallbackDispatcher;
    ULONG BreakpointWithStatus;
    ULONG DebuggerDataList;
} DBGKD_GET_VERSION32, *PDBGKD_GET_VERSION32;

typedef struct _DBGKD_DEBUG_DATA_HEADER32
{
    LIST_ENTRY32 List;
    ULONG OwnerTag;
    ULONG Size;
} DBGKD_DEBUG_DATA_HEADER32, *PDBGKD_DEBUG_DATA_HEADER32;

typedef struct _KDDEBUGGER_DATA32
{
    DBGKD_DEBUG_DATA_HEADER32 Header;
    ULONG KernBase;
    ULONG BreakpointWithStatus;
    ULONG SavedContext;
    USHORT ThCallbackStack;
    USHORT NextCallback;
    USHORT FramePointer;
    USHORT PaeEnabled:1;
    ULONG KiCallUserMode;
    ULONG KeUserCallbackDispatcher;
    ULONG PsLoadedModuleList;
    ULONG PsActiveProcessHead;
    ULONG PspCidTable;
    ULONG ExpSystemResourcesList;
    ULONG ExpPagedPoolDescriptor;
    ULONG ExpNumberOfPagedPools;
    ULONG KeTimeIncrement;
    ULONG KeBugCheckCallbackListHead;
    ULONG KiBugcheckData;
    ULONG IopErrorLogListHead;
    ULONG ObpRootDirectoryObject;
    ULONG ObpTypeObjectType;
    ULONG MmSystemCacheStart;
    ULONG MmSystemCacheEnd;
    ULONG MmSystemCacheWs;
    ULONG MmPfnDatabase;
    ULONG MmSystemPtesStart;
    ULONG MmSystemPtesEnd;
    ULONG MmSubsectionBase;
    ULONG MmNumberOfPagingFiles;
    ULONG MmLowestPhysicalPage;
    ULONG MmHighestPhysicalPage;
    ULONG MmNumberOfPhysicalPages;
    ULONG MmMaximumNonPagedPoolInBytes;
    ULONG MmNonPagedSystemStart;
    ULONG MmNonPagedPoolStart;
    ULONG MmNonPagedPoolEnd;
    ULONG MmPagedPoolStart;
    ULONG MmPagedPoolEnd;
    ULONG MmPagedPoolInformation;
    ULONG MmPageSize;
    ULONG MmSizeOfPagedPoolInBytes;
    ULONG MmTotalCommitLimit;
    ULONG MmTotalCommittedPages;
    ULONG MmSharedCommit;
    ULONG MmDriverCommit;
    ULONG MmProcessCommit;
    ULONG MmPagedPoolCommit;
    ULONG MmExtendedCommit;
    ULONG MmZeroedPageListHead;
    ULONG MmFreePageListHead;
    ULONG MmStandbyPageListHead;
    ULONG MmModifiedPageListHead;
    ULONG MmModifiedNoWritePageListHead;
    ULONG MmAvailablePages;
    ULONG MmResidentAvailablePages;
    ULONG PoolTrackTable;
    ULONG NonPagedPoolDescriptor;
    ULONG MmHighestUserAddress;
    ULONG MmSystemRangeStart;
    ULONG MmUserProbeAddress;
    ULONG KdPrintCircularBuffer;
    ULONG KdPrintCircularBufferEnd;
    ULONG KdPrintWritePointer;
    ULONG KdPrintRolloverCount;
    ULONG MmLoadedUserImageList;
} KDDEBUGGER_DATA32, *PKDDEBUGGER_DATA32;

typedef struct _DBGKD_GET_VERSION64
{
    USHORT MajorVersion;
    USHORT MinorVersion;
    UCHAR ProtocolVersion;
    UCHAR KdSecondaryVersion;
    USHORT Flags;
    USHORT MachineType;
    UCHAR MaxPacketType;
    UCHAR MaxStateChange;
    UCHAR MaxManipulate;
    UCHAR Simulation;
    USHORT Unused[1];
    ULONG64 KernBase;
    ULONG64 PsLoadedModuleList;
    ULONG64 DebuggerDataList;
} DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;

typedef struct _DBGKD_DEBUG_DATA_HEADER64
{
    LIST_ENTRY64 List;
    ULONG OwnerTag;
    ULONG Size;
} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;

typedef union _GCC_ULONG64
{
    ULONG_PTR Pointer;
    ULONG64 RealPointer;
} GCC_ULONG64, *PGCC_ULONG64;

typedef struct _KDDEBUGGER_DATA64
{
    DBGKD_DEBUG_DATA_HEADER64 Header;
    ULONG64 KernBase;
    GCC_ULONG64 BreakpointWithStatus;
    ULONG64 SavedContext;
    USHORT ThCallbackStack;
    USHORT NextCallback;
    USHORT FramePointer;
    USHORT PaeEnabled:1;
    GCC_ULONG64 KiCallUserMode;
    ULONG64 KeUserCallbackDispatcher;
    GCC_ULONG64 PsLoadedModuleList;
    GCC_ULONG64 PsActiveProcessHead;
    GCC_ULONG64 PspCidTable;
    GCC_ULONG64 ExpSystemResourcesList;
    GCC_ULONG64 ExpPagedPoolDescriptor;
    GCC_ULONG64 ExpNumberOfPagedPools;
    GCC_ULONG64 KeTimeIncrement;
    GCC_ULONG64 KeBugCheckCallbackListHead;
    GCC_ULONG64 KiBugcheckData;
    GCC_ULONG64 IopErrorLogListHead;
    GCC_ULONG64 ObpRootDirectoryObject;
    GCC_ULONG64 ObpTypeObjectType;
    GCC_ULONG64 MmSystemCacheStart;
    GCC_ULONG64 MmSystemCacheEnd;
    GCC_ULONG64 MmSystemCacheWs;
    GCC_ULONG64 MmPfnDatabase;
    GCC_ULONG64 MmSystemPtesStart;
    GCC_ULONG64 MmSystemPtesEnd;
    GCC_ULONG64 MmSubsectionBase;
    GCC_ULONG64 MmNumberOfPagingFiles;
    GCC_ULONG64 MmLowestPhysicalPage;
    GCC_ULONG64 MmHighestPhysicalPage;
    GCC_ULONG64 MmNumberOfPhysicalPages;
    GCC_ULONG64 MmMaximumNonPagedPoolInBytes;
    GCC_ULONG64 MmNonPagedSystemStart;
    GCC_ULONG64 MmNonPagedPoolStart;
    GCC_ULONG64 MmNonPagedPoolEnd;
    GCC_ULONG64 MmPagedPoolStart;
    GCC_ULONG64 MmPagedPoolEnd;
    GCC_ULONG64 MmPagedPoolInformation;
    ULONG64 MmPageSize;
    GCC_ULONG64 MmSizeOfPagedPoolInBytes;
    GCC_ULONG64 MmTotalCommitLimit;
    GCC_ULONG64 MmTotalCommittedPages;
    GCC_ULONG64 MmSharedCommit;
    GCC_ULONG64 MmDriverCommit;
    GCC_ULONG64 MmProcessCommit;
    GCC_ULONG64 MmPagedPoolCommit;
    GCC_ULONG64 MmExtendedCommit;
    GCC_ULONG64 MmZeroedPageListHead;
    GCC_ULONG64 MmFreePageListHead;
    GCC_ULONG64 MmStandbyPageListHead;
    GCC_ULONG64 MmModifiedPageListHead;
    GCC_ULONG64 MmModifiedNoWritePageListHead;
    GCC_ULONG64 MmAvailablePages;
    GCC_ULONG64 MmResidentAvailablePages;
    GCC_ULONG64 PoolTrackTable;
    GCC_ULONG64 NonPagedPoolDescriptor;
    GCC_ULONG64 MmHighestUserAddress;
    GCC_ULONG64 MmSystemRangeStart;
    GCC_ULONG64 MmUserProbeAddress;
    GCC_ULONG64 KdPrintCircularBuffer;
    GCC_ULONG64 KdPrintCircularBufferEnd;
    GCC_ULONG64 KdPrintWritePointer;
    GCC_ULONG64 KdPrintRolloverCount;
    GCC_ULONG64 MmLoadedUserImageList;
    GCC_ULONG64 NtBuildLab;
    GCC_ULONG64 KiNormalSystemCall;
    GCC_ULONG64 KiProcessorBlock;
    GCC_ULONG64 MmUnloadedDrivers;
    GCC_ULONG64 MmLastUnloadedDriver;
    GCC_ULONG64 MmTriageActionTaken;
    GCC_ULONG64 MmSpecialPoolTag;
    GCC_ULONG64 KernelVerifier;
    GCC_ULONG64 MmVerifierData;
    GCC_ULONG64 MmAllocatedNonPagedPool;
    GCC_ULONG64 MmPeakCommitment;
    GCC_ULONG64 MmTotalCommitLimitMaximum;
    GCC_ULONG64 CmNtCSDVersion;
    GCC_ULONG64 MmPhysicalMemoryBlock;
    GCC_ULONG64 MmSessionBase;
    GCC_ULONG64 MmSessionSize;
    GCC_ULONG64 MmSystemParentTablePage;
    GCC_ULONG64 MmVirtualTranslationBase;
    USHORT OffsetKThreadNextProcessor;
    USHORT OffsetKThreadTeb;
    USHORT OffsetKThreadKernelStack;
    USHORT OffsetKThreadInitialStack;
    USHORT OffsetKThreadApcProcess;
    USHORT OffsetKThreadState;
    USHORT OffsetKThreadBStore;
    USHORT OffsetKThreadBStoreLimit;
    USHORT SizeEProcess;
    USHORT OffsetEprocessPeb;
    USHORT OffsetEprocessParentCID;
    USHORT OffsetEprocessDirectoryTableBase;
    USHORT SizePrcb;
    USHORT OffsetPrcbDpcRoutine;
    USHORT OffsetPrcbCurrentThread;
    USHORT OffsetPrcbMhz;
    USHORT OffsetPrcbCpuType;
    USHORT OffsetPrcbVendorString;
    USHORT OffsetPrcbProcStateContext;
    USHORT OffsetPrcbNumber;
    USHORT SizeEThread;
    GCC_ULONG64 KdPrintCircularBufferPtr;
    GCC_ULONG64 KdPrintBufferSize;
    GCC_ULONG64 KeLoaderBlock;
    USHORT SizePcr;
    USHORT OffsetPcrSelfPcr;
    USHORT OffsetPcrCurrentPrcb;
    USHORT OffsetPcrContainedPrcb;
    USHORT OffsetPcrInitialBStore;
    USHORT OffsetPcrBStoreLimit;
    USHORT OffsetPcrInitialStack;
    USHORT OffsetPcrStackLimit;
    USHORT OffsetPrcbPcrPage;
    USHORT OffsetPrcbProcStateSpecialReg;
    USHORT GdtR0Code;
    USHORT GdtR0Data;
    USHORT GdtR0Pcr;
    USHORT GdtR3Code;
    USHORT GdtR3Data;
    USHORT GdtR3Teb;
    USHORT GdtLdt;
    USHORT GdtTss;
    USHORT Gdt64R3CmCode;
    USHORT Gdt64R3CmTeb;
    GCC_ULONG64 IopNumTriageDumpDataBlocks;
    GCC_ULONG64 IopTriageDumpDataBlocks;
#if 0 // Longhorn/Vista and later
    GCC_ULONG64 VfCrashDataBlock;
    GCC_ULONG64 MmBadPagesDetected;
    GCC_ULONG64 MmZeroedPageSingleBitErrorsDetected;
#endif
} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;

typedef VOID
(__cdecl *PWINDBG_OUTPUT_ROUTINE)(
    _In_ PCSTR lpFormat,
    ...);

typedef ULONG_PTR
(NTAPI *PWINDBG_GET_EXPRESSION)(
    _In_ PCSTR lpExpression);

typedef VOID
(NTAPI *PWINDBG_GET_SYMBOL)(
    _In_ PVOID Offset,
    _Out_ PCHAR pchBuffer,
    _Out_ ULONG_PTR* pDisplacement);

typedef ULONG
(NTAPI *PWINDBG_DISASM)(
    _Inout_ ULONG_PTR* lpOffset,
    _In_ PCSTR lpBuffer,
    _In_ ULONG fShowEffectiveAddress);

typedef ULONG
(NTAPI *PWINDBG_READ_PROCESS_MEMORY_ROUTINE)(
    _In_ ULONG_PTR Offset,
    _Out_ PVOID lpBuffer,
    _In_ ULONG cb,
    _Out_ PULONG lpcbBytesRead);

typedef ULONG
(NTAPI *PWINDBG_SET_THREAD_CONTEXT_ROUTINE)(
    _In_ ULONG Processor,
    _In_ PCONTEXT lpContext,
    _In_ ULONG cbSizeOfContext);

typedef ULONG
(NTAPI *PWINDBG_GET_THREAD_CONTEXT_ROUTINE)(
    _In_ ULONG Processor,
    _Out_ PCONTEXT lpContext,
    _In_ ULONG cbSizeOfContext);

typedef struct _EXTSTACKTRACE
{
    ULONG_PTR FramePointer;
    ULONG_PTR ProgramCounter;
    ULONG_PTR ReturnAddress;
    ULONG_PTR Args[4];
} EXTSTACKTRACE, *PEXTSTACKTRACE;

typedef ULONG
(NTAPI *PWINDBG_IOCTL_ROUTINE)(
    _In_ USHORT IoctlType,
    _Inout_ PVOID lpvData,
    _In_ ULONG cbSize);

typedef ULONG
(NTAPI *PWINDBG_STACKTRACE_ROUTINE)(
    _In_ ULONG_PTR FramePointer,
    _In_ ULONG_PTR StackPointer,
    _In_ ULONG_PTR ProgramCounter,
    _Out_ PEXTSTACKTRACE StackFrames,
    _In_ ULONG Frames);

typedef struct _WINDBG_EXTENSION_APIS
{
    PWINDBG_OUTPUT_ROUTINE lpOutputRoutine;
    PWINDBG_GET_EXPRESSION lpGetExpressionRoutine;
    PWINDBG_GET_SYMBOL lpGetSymbolRoutine;
    PWINDBG_DISASM lpDisasmRoutine;
    PWINDBG_READ_PROCESS_MEMORY_ROUTINE lpReadProcessMemoryRoutine;
    PWINDBG_GET_THREAD_CONTEXT_ROUTINE lpGetThreadContextRoutine;
    PWINDBG_SET_THREAD_CONTEXT_ROUTINE lpSetThreadContextRoutine;
    PWINDBG_IOCTL_ROUTINE lpIoctlRoutine;
    PWINDBG_STACKTRACE_ROUTINE lpStackTraceRoutine;
} WINDBG_EXTENSION_APIS, *PWINDBG_EXTENSION_APIS;

#define IG_GET_DEBUGGER_DATA             14

#define DBG_DUMP_LIST                  0x00020
#define DBG_DUMP_ADDRESS_OF_FIELD      0x10000

#define DBG_DUMP_FIELD_COPY_FIELD_DATA 0x00020
#define DBG_DUMP_FIELD_RETURN_ADDRESS  0x01000
typedef struct _FIELD_INFO
{
    PCSZ fName;
    ULONG fOptions;
    ULONG64 address;
    PVOID pBuffer;
} FIELD_INFO, *PFIELD_INFO;

typedef ULONG
(NTAPI *PSYM_DUMP_FIELD_CALLBACK)(
    _In_ PFIELD_INFO pField,
    _In_ PVOID UserContext);

typedef struct _SYM_DUMP_PARAM
{
    ULONG size;
    PCSZ sName;
    ULONG Options;
    ULONG64 addr;
    PVOID Context;
    PSYM_DUMP_FIELD_CALLBACK CallbackRoutine;
    ULONG nFields;
    PFIELD_INFO Fields;
} SYM_DUMP_PARAM, *PSYM_DUMP_PARAM;

#define IG_DUMP_SYMBOL_INFO              22

#define IG_GET_CURRENT_THREAD            25
typedef struct _GET_CURRENT_THREAD_ADDRESS {
    ULONG Processor;
    ULONG64 Address;
} GET_CURRENT_THREAD_ADDRESS, *PGET_CURRENT_THREAD_ADDRESS;

#define IG_GET_CURRENT_PROCESS           26
typedef struct _GET_CURRENT_PROCESS_ADDRESS {
    ULONG Processor;
    ULONG64 CurrentThread;
    ULONG64 Address;
} GET_CURRENT_PROCESS_ADDRESS, *PGET_CURRENT_PROCESS_ADDRESS;

#define IG_GET_EXPRESSION_EX             30
typedef struct _GET_EXPRESSION_EX {
    PCSTR Expression;
    PCSTR Remainder;
    ULONG64 Value;
} GET_EXPRESSION_EX, *PGET_EXPRESSION_EX;

#ifndef NOEXTAPI

#define DECLARE_API(s)              \
    VOID NTAPI                      \
    s( _In_ HANDLE hCurrentProcess, \
       _In_ HANDLE hCurrentThread, \
       _In_ ULONG dwCurrentPc,     \
       _In_ ULONG dwProcessor,     \
       _In_ PCSTR args)

extern WINDBG_EXTENSION_APIS ExtensionApis;

#define dprintf       (ExtensionApis.lpOutputRoutine)
#define GetExpression (ExtensionApis.lpGetExpressionRoutine)
#define GetSymbol     (ExtensionApis.lpGetSymbolRoutine)
#define Disasm        (ExtensionApis.lpDisasmRoutine)
#define ReadMemory    (ExtensionApis.lpReadProcessMemoryRoutine)
#define GetContext    (ExtensionApis.lpGetThreadContextRoutine)
#define SetContext    (ExtensionApis.lpSetThreadContextRoutine)
#define Ioctl         (ExtensionApis.lpIoctlRoutine)
#define StackTrace    (ExtensionApis.lpStackTraceRoutine)

FORCEINLINE
ULONG
GetDebuggerData(
    _In_ ULONG Tag,
    _Inout_ PVOID Buffer,
    _In_ ULONG Size)
{
    ((PDBGKD_DEBUG_DATA_HEADER64)Buffer)->OwnerTag = Tag;
    ((PDBGKD_DEBUG_DATA_HEADER64)Buffer)->Size = Size;
    return Ioctl(IG_GET_DEBUGGER_DATA, Buffer, Size);
}

FORCEINLINE
VOID
GetCurrentThreadAddr(
    _In_ ULONG Processor,
    _Out_ PULONG64 Address)
{
    GET_CURRENT_THREAD_ADDRESS gcta;
    gcta.Processor = Processor;

    Ioctl(IG_GET_CURRENT_THREAD, (PVOID)&gcta, sizeof(gcta));

    *Address = gcta.Address;
}

FORCEINLINE
VOID
GetCurrentProcessAddr(
    _In_ ULONG Processor,
    _In_ ULONG64 CurrentThread,
    _Out_ PULONG64 Address)
{
    GET_CURRENT_PROCESS_ADDRESS gcpa;
    gcpa.Processor = Processor;
    gcpa.CurrentThread = CurrentThread;

    Ioctl(IG_GET_CURRENT_PROCESS, (PVOID)&gcpa, sizeof(gcpa));

    *Address = gcpa.Address;
}

FORCEINLINE
ULONG
GetExpressionEx(
    _In_ PCSTR Expression,
    _Out_ PULONG64 Value,
    _Out_opt_ PCSTR *Remainder)
{
    GET_EXPRESSION_EX gee;
    gee.Expression = Expression;

    if (!Ioctl(IG_GET_EXPRESSION_EX, (PVOID)&gee, sizeof(gee)))
        return FALSE;

    *Value = gee.Value;
    if (Remainder)
        *Remainder = gee.Remainder;
    return TRUE;
}

FORCEINLINE
ULONG
GetFieldData(
    _In_ ULONG64 TypeAddress,
    _In_ LPCSTR Type,
    _In_ LPCSTR Field,
    _In_ ULONG OutSize,
    _Out_ PVOID pOutValue)
{
    FIELD_INFO FieldInfo = {0};
    SYM_DUMP_PARAM Sym = {0};

    FieldInfo.fName = Field;
    FieldInfo.fOptions = DBG_DUMP_FIELD_COPY_FIELD_DATA | DBG_DUMP_FIELD_RETURN_ADDRESS;
    FieldInfo.pBuffer = pOutValue;
    Sym.size = sizeof(Sym);
    Sym.sName = Type;
    Sym.addr = TypeAddress;
    Sym.nFields = 1;
    Sym.Fields = &FieldInfo;

    RtlZeroMemory(pOutValue, OutSize);
    return Ioctl(IG_DUMP_SYMBOL_INFO, &Sym, sizeof(Sym));
}

#define GetFieldValue(Addr, Type, Field, OutValue) GetFieldData(Addr, Type, Field, sizeof(OutValue), &(OutValue))

static inline
ULONG64
GetShortField(
    _In_ ULONG64 TypeAddress,
    _In_ LPCSTR Name,
    _In_ USHORT StoreAddress)
{
    static ULONG64 SavedAddress;
    static PCSZ SavedName;
    FIELD_INFO FieldInfo = {0};
    SYM_DUMP_PARAM Sym = {0};

    FieldInfo.fName = Name;
    Sym.size = sizeof(Sym);

    if (StoreAddress)
    {
        Sym.sName = Name;
        Sym.nFields = 0;
        SavedName = Name;
        Sym.addr = SavedAddress = TypeAddress;
        return Ioctl(IG_DUMP_SYMBOL_INFO, &Sym, sizeof(Sym));
    }
    else
    {
        Sym.sName = SavedName;
        Sym.nFields = 1;
        Sym.Fields = &FieldInfo;
        Sym.addr = SavedAddress;
        return Ioctl(IG_DUMP_SYMBOL_INFO, &Sym, sizeof(Sym)) ? FieldInfo.address : 0;
    }
}

#define InitTypeRead(Addr, Type) GetShortField(Addr, #Type, 1)
#define ReadField(Field) GetShortField(0, #Field, 0)

FORCEINLINE
ULONG
ListType(
    _In_ LPCSTR Type,
    _In_ ULONG64 Address,
    _In_ USHORT ListByFieldAddress,
    _In_ LPCSTR NextPointer,
    _In_ PVOID Context,
    _In_ PSYM_DUMP_FIELD_CALLBACK CallbackRoutine)
{
    FIELD_INFO FieldInfo = {0};
    SYM_DUMP_PARAM Sym = {0};

    FieldInfo.fName = NextPointer;
    Sym.size = sizeof(Sym);
    Sym.sName = Type;
    Sym.Options = DBG_DUMP_LIST;
    Sym.addr = Address;
    Sym.nFields = 1;
    Sym.Fields = &FieldInfo;
    Sym.Context = Context;
    Sym.CallbackRoutine = CallbackRoutine;

    if (ListByFieldAddress)
        Sym.Options |= DBG_DUMP_ADDRESS_OF_FIELD;

    return Ioctl(IG_DUMP_SYMBOL_INFO, &Sym, sizeof(Sym));
}

#endif

#endif
