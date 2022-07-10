/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/kd/arm/kdbg.c
 * PURPOSE:         Serial Port Kernel Debugging Transport Library
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include <arm/peripherals/pl011.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

CPPORT DefaultPort = {0, 0, 0};

//
// We need to build this in the configuration root and use KeFindConfigurationEntry
// to recover it later.
//
#define HACK 24000000

/* REACTOS FUNCTIONS **********************************************************/

VOID
NTAPI
KdPortPutByteEx(IN PCPPORT PortInformation,
                IN UCHAR ByteToSend)
{
    //
    // Wait for ready
    //
    while ((READ_REGISTER_ULONG((PULONG)UART_PL01x_FR) & UART_PL01x_FR_TXFF) != 0);

    //
    // Send the character
    //
    WRITE_REGISTER_ULONG((PULONG)UART_PL01x_DR, ByteToSend);
}

/* EOF */
