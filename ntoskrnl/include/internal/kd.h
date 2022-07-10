#pragma once

#include <cportlib/cportlib.h>

//
// Kernel Debugger Port Definition
//

BOOLEAN
NTAPI
KdPortInitializeEx(
    PCPPORT PortInformation,
    ULONG ComPortNumber
);

BOOLEAN
NTAPI
KdPortGetByteEx(
    PCPPORT PortInformation,
    PUCHAR ByteReceived);

VOID
NTAPI
KdPortPutByteEx(
    PCPPORT PortInformation,
    UCHAR ByteToSend
);

/* SYMBOL ROUTINES **********************************************************/

#ifdef _NTOSKRNL_

#ifdef KDBG
# define KdbInit()                                  KdbpCliInit()
#else
# define KdbInit()                                      do { } while (0)
#endif

/* KD ROUTINES ***************************************************************/

typedef enum _KD_CONTINUE_TYPE
{
    kdContinue = 0,
    kdDoNotHandleException,
    kdHandleException
} KD_CONTINUE_TYPE;

/* INIT ROUTINES *************************************************************/

BOOLEAN
NTAPI
KdInitSystem(
    ULONG Reserved,
    PLOADER_PARAMETER_BLOCK LoaderBlock
);

VOID
KdpScreenAcquire(VOID);

VOID
KdpScreenRelease(VOID);

VOID
NTAPI
KdbInitialize(ULONG BootPhase);

VOID
NTAPI
KdbDebugPrint(
    PCH Message,
    ULONG Length);

/* KD ROUTINES ***************************************************************/

BOOLEAN
NTAPI
KdpDetectConflicts(PCM_RESOURCE_LIST DriverList);

BOOLEAN
NTAPI
KdpSafeReadMemory(
    IN ULONG_PTR Addr,
    IN LONG Len,
    OUT PVOID Value
);

BOOLEAN
NTAPI
KdpSafeWriteMemory(
    IN ULONG_PTR Addr,
    IN LONG Len,
    IN ULONGLONG Value
);


/* KD GLOBALS  ***************************************************************/

/* Serial debug connection */
#define DEFAULT_DEBUG_PORT      2 /* COM2 */
#define DEFAULT_DEBUG_COM1_IRQ  4 /* COM1 IRQ */
#define DEFAULT_DEBUG_COM2_IRQ  3 /* COM2 IRQ */
#define DEFAULT_DEBUG_BAUD_RATE 115200 /* 115200 Baud */

/* KD Internal Debug Services */
typedef enum _KDP_DEBUG_SERVICE
{
    DumpNonPagedPool = 0x1e, /* a */
    ManualBugCheck = 0x30, /* b */
    DumpNonPagedPoolStats = 0x2e, /* c */
    DumpNewNonPagedPool = 0x20, /* d */
    DumpNewNonPagedPoolStats = 0x12, /* e */
    DumpAllThreads = 0x21, /* f */
    DumpUserThreads = 0x22, /* g */
    KdSpare1 = 0x23, /* h */
    KdSpare2 = 0x17, /* i */
    KdSpare3 = 0x24, /* j */
    EnterDebugger = 0x25,  /* k */
    ThatsWhatSheSaid = 69 /* FIGURE IT OUT */
} KDP_DEBUG_SERVICE;

#endif

#if DBG && defined(_M_IX86) && !defined(_WINKD_) // See ke/i386/traphdlr.c
#define ID_Win32PreServiceHook 'WSH0'
#define ID_Win32PostServiceHook 'WSH1'
typedef void (NTAPI *PKDBG_PRESERVICEHOOK)(ULONG, PULONG_PTR);
typedef ULONG_PTR (NTAPI *PKDBG_POSTSERVICEHOOK)(ULONG, ULONG_PTR);
extern PKDBG_PRESERVICEHOOK KeWin32PreServiceHook;
extern PKDBG_POSTSERVICEHOOK KeWin32PostServiceHook;
#endif
