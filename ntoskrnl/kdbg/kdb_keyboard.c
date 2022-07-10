/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/kdbg/kdb_keyboard.c
 * PURPOSE:         Keyboard driver
 *
 * PROGRAMMERS:     Victor Kirhenshtein (sauros@iname.com)
 *                  Jason Filby (jasonfilby@yahoo.com)
 */

/* INCLUDES ****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>


#define KBD_STATUS_REG          0x64
#define KBD_CNTL_REG            0x64
#define KBD_DATA_REG            0x60

#define KBD_STAT_OBF            0x01
#define KBD_STAT_IBF            0x02

#define CTRL_WRITE_MOUSE        0xD4
#define MOU_ENAB                0xF4
#define MOU_DISAB               0xF5
#define MOUSE_ACK               0xFA

#define KBD_DISABLE_MOUSE       0xA7
#define KBD_ENABLE_MOUSE        0xA8

#define kbd_write_command(cmd)  WRITE_PORT_UCHAR((PUCHAR)KBD_CNTL_REG,cmd)
#define kbd_write_data(cmd)     WRITE_PORT_UCHAR((PUCHAR)KBD_DATA_REG,cmd)
#define kbd_read_input()        READ_PORT_UCHAR((PUCHAR)KBD_DATA_REG)
#define kbd_read_status()       READ_PORT_UCHAR((PUCHAR)KBD_STATUS_REG)

typedef UCHAR byte_t;

/* FUNCTIONS *****************************************************************/

static VOID
KbdSendCommandToMouse(UCHAR Command)
{
    ULONG Retry = 20000;

    while (kbd_read_status() & KBD_STAT_OBF && Retry--)
    {
        kbd_read_input();
        KeStallExecutionProcessor(50);
    }

    Retry = 20000;
    while (kbd_read_status() & KBD_STAT_IBF && Retry--)
        KeStallExecutionProcessor(50);

    kbd_write_command(CTRL_WRITE_MOUSE);

    Retry = 20000;
    while (kbd_read_status() & KBD_STAT_IBF && Retry--)
        KeStallExecutionProcessor(50);

    kbd_write_data(Command);

    Retry = 20000;
    while (!(kbd_read_status() & KBD_STAT_OBF) && Retry--)
        KeStallExecutionProcessor(50);

    if (kbd_read_input() != MOUSE_ACK) { ; }

    return;
}

VOID KbdEnableMouse()
{
    KbdSendCommandToMouse(MOU_ENAB);
}

VOID KbdDisableMouse()
{
    KbdSendCommandToMouse(MOU_DISAB);
}

/* EOF */
