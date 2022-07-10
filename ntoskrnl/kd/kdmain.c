/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Kernel
 * FILE:            ntoskrnl/kd/kdmain.c
 * PURPOSE:         Kernel Debugger Initialization
 *
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 */

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#undef KdDebuggerInitialize0
#undef KdDebuggerInitialize1
#undef KdSendPacket
#undef KdReceivePacket

/* PUBLIC FUNCTIONS *********************************************************/

NTSTATUS
NTAPI
KdpDebuggerInitialize0(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock OPTIONAL)
{
    KdbInitialize(0);

    return KdDebuggerInitialize0(LoaderBlock);
}

NTSTATUS
NTAPI
KdpDebuggerInitialize1(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock OPTIONAL)
{
    KdbInitialize(1);

    NtGlobalFlag |= FLG_STOP_ON_EXCEPTION;

    return KdDebuggerInitialize1(LoaderBlock);
}

 /* EOF */
