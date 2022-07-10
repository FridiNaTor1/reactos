#define NOEXTAPI
#include <ntifs.h>
#include <halfuncs.h>
#include <stdio.h>
#include <stdlib.h>
#include <arc/arc.h>
#include <windbgkd.h>
#include <kddll.h>
#include <cportlib/cportlib.h>
#include <ndk/inbvfuncs.h>
#include <drivers/bootvid/bootvid.h>

#define KEY_BS          8
#define KEY_ESC         27
#define KEY_DEL         127

#define KEY_SCAN_UP     72
#define KEY_SCAN_DOWN   80

/* These values MUST be nonzero.  They're used as bit masks. */
typedef enum _KDB_OUTPUT_SETTINGS
{
   KD_DEBUG_KDSERIAL = 1,
   KD_DEBUG_KDNOECHO = 2
} KDB_OUTPUT_SETTINGS;
extern ULONG KdbDebugState;

VOID
KdpPrintString(
    _In_ PSTRING Output);

VOID
KdpCommandHistoryAppend(
    IN PCHAR Command);

VOID
KdpReadCommand(
    _Inout_ PSTRING ResponseString);

CHAR
KdpTryGetChar(
    _Out_ PULONG ScanCode,
    _In_ ULONG Retry);
