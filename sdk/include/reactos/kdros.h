


#pragma once

#if 0

FORCEINLINE
VOID
KdRosDumpAllThreads(VOID)
{
    KdSystemDebugControl(' soR', (PVOID)DumpAllThreads, 0, 0, 0, 0, 0);
}

FORCEINLINE
VOID
KdRosDumpUserThreads(VOID)
{
    KdSystemDebugControl(' soR', (PVOID)DumpUserThreads, 0, 0, 0, 0, 0);
}

FORCEINLINE
VOID
KdRosDumpArmPfnDatabase(VOID)
{
    KdSystemDebugControl(' soR', (PVOID)KdSpare3, 0, 0, 0, 0, 0);
}
#endif

FORCEINLINE
VOID
KdRosSetDebugCallback(
    ULONG Id,
    PVOID Callback)
{
    KdSystemDebugControl((SYSDBG_COMMAND)'CsoR', Callback, Id, 0, 0, 0, 0);
}

FORCEINLINE
VOID
KdRosDumpStackFrames(
    ULONG Count,
    PULONG_PTR Backtrace)
{
    KdSystemDebugControl((SYSDBG_COMMAND)'DsoR', Backtrace, Count, 0, 0, 0, 0);
}

#if defined(KDBG)
typedef
VOID
(NTAPI KDBG_EXTENSION_ROUTINE)(
    _In_ HANDLE hCurrentProcess,
    _In_ HANDLE hCurrentThread,
    _In_ ULONG dwCurrentPc,
    _In_ ULONG dwProcessor,
    _In_ PCSTR args);
typedef KDBG_EXTENSION_ROUTINE *PKDBG_EXTENSION_ROUTINE;

typedef struct _KDBG_EXTENSION_API
{
    PCSZ Name;
    PCSZ Syntax;
    PCSZ Help;
    PKDBG_EXTENSION_ROUTINE Routine;
} KDBG_EXTENSION_API, *PKDBG_EXTENSION_API;

typedef struct _WINDBG_EXTENSION_APIS *PWINDBG_EXTENSION_APIS;
typedef
VOID
(NTAPI KDBG_EXTENSION_INIT)(
    _In_ PWINDBG_EXTENSION_APIS lpExtensionApis,
    _In_ USHORT usMajorVersion,
    _In_ USHORT usMinorVersion);
typedef KDBG_EXTENSION_INIT *PKDBG_EXTENSION_INIT;

typedef struct _KDBG_CLI_REGISTRATION
{
    PKDBG_EXTENSION_INIT InitRoutine;
    KDBG_EXTENSION_API Api[];
} KDBG_CLI_REGISTRATION, *PKDBG_CLI_REGISTRATION;

FORCEINLINE
ULONG
KdRosRegisterCliExtension(
    _In_ PKDBG_CLI_REGISTRATION Registration)
{
    return KdSystemDebugControl((SYSDBG_COMMAND)'EbdK', Registration, FALSE, 0, 0, 0, 0);
}

typedef
BOOLEAN
(NTAPI KDBG_CLI_ROUTINE)(
    IN PCHAR Command,
    IN ULONG Argc,
    IN PCH Argv[]);
typedef KDBG_CLI_ROUTINE *PKDBG_CLI_ROUTINE;

FORCEINLINE
ULONG
KdRosRegisterCliCallback(
    PKDBG_CLI_ROUTINE Callback)
{
    return KdSystemDebugControl((SYSDBG_COMMAND)'RbdK', (PVOID)Callback, FALSE, 0, 0, 0, 0);
}

FORCEINLINE
VOID
KdRosDeregisterCliCallback(
    PKDBG_CLI_ROUTINE Callback)
{
    KdSystemDebugControl((SYSDBG_COMMAND)'RbdK', (PVOID)Callback, TRUE, 0, 0, 0, 0);
}
#endif

