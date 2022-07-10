/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdcom/kdbg.c
 * PURPOSE:         Serial i/o functions for the kernel debugger.
 * PROGRAMMER:      Alex Ionescu
 *                  Hervé Poussineau
 */

/* INCLUDES *****************************************************************/

#include "kdrosdbg.h"
#define NDEBUG
#include <debug.h>

#if defined(SARCH_PC98)
#define DEFAULT_BAUD_RATE   9600
#else
#define DEFAULT_BAUD_RATE   19200
#endif

#if defined(_M_IX86) || defined(_M_AMD64)
#if defined(SARCH_PC98)
const ULONG BaseArray[] = {0, 0x30, 0x238};
#else
const ULONG BaseArray[] = {0, 0x3F8, 0x2F8, 0x3E8, 0x2E8};
#endif
#elif defined(_M_PPC)
const ULONG BaseArray[] = {0, 0x800003F8};
#elif defined(_M_MIPS)
const ULONG BaseArray[] = {0, 0x80006000, 0x80007000};
#elif defined(_M_ARM)
const ULONG BaseArray[] = {0, 0xF1012000};
#else
#error Unknown architecture
#endif

/* KD Private Debug Modes */
typedef struct _KDP_DEBUG_MODE
{
    union
    {
        struct
        {
            /* Native Modes */
            UCHAR Screen :1;
            UCHAR Serial :1;
            UCHAR File :1;
        };

        /* Generic Value */
        ULONG Value;
    };
} KDP_DEBUG_MODE;

ULONG KdbDebugState = 0; /* KDBG Settings (NOECHO, KDSERIAL) */
KDP_DEBUG_MODE KdpDebugMode;
STRING KdbPromptString = RTL_CONSTANT_STRING("kdb:> ");

#define KdpScreenLineLengthDefault 80
static CHAR KdpScreenLineBuffer[KdpScreenLineLengthDefault + 1] = "";
static ULONG KdpScreenLineBufferPos = 0, KdpScreenLineLength = 0;

/* Port Information for the Serial Native Mode */
ULONG  SerialPortNumber;
CPPORT SerialPortInfo;

static ULONG KdpBufferSize = 0;
static CHAR KdpDebugBufferStatic[4096];
static PCHAR KdpDebugBuffer = NULL;
static volatile ULONG KdpCurrentPosition = 0;
static volatile ULONG KdpFreeBytes = 0;
ANSI_STRING KdpLogFileName = RTL_CONSTANT_STRING("\\SystemRoot\\debug.log");
static KSPIN_LOCK KdpDebugLogSpinLock;
static KEVENT KdpLoggerThreadEvent;
static HANDLE KdpLogFileHandle;

static VOID
NTAPI
KdbpGetCommandLineSettings(
    PCHAR p1)
{
#define CONST_STR_LEN(x) (sizeof(x)/sizeof(x[0]) - 1)

    while (p1 && (p1 = strchr(p1, ' ')))
    {
        /* Skip other spaces */
        while (*p1 == ' ') ++p1;

        if (!_strnicmp(p1, "KDSERIAL", CONST_STR_LEN("KDSERIAL")))
        {
            p1 += CONST_STR_LEN("KDSERIAL");
            KdbDebugState |= KD_DEBUG_KDSERIAL;
            KdpDebugMode.Serial = TRUE;
        }
        else if (!_strnicmp(p1, "KDNOECHO", CONST_STR_LEN("KDNOECHO")))
        {
            p1 += CONST_STR_LEN("KDNOECHO");
            KdbDebugState |= KD_DEBUG_KDNOECHO;
        }
    }
}

static PCHAR
NTAPI
KdpGetDebugMode(PCHAR Currentp2)
{
    PCHAR p1, p2 = Currentp2;
    ULONG Value;

    /* Check for Screen Debugging */
    if (!_strnicmp(p2, "SCREEN", 6))
    {
        /* Enable It */
        p2 += 6;
        KdpDebugMode.Screen = TRUE;
    }
    /* Check for Serial Debugging */
    else if (!_strnicmp(p2, "COM", 3))
    {
        /* Gheck for a valid Serial Port */
        p2 += 3;
        if (*p2 != ':')
        {
            Value = (ULONG)atol(p2);
            if (Value > 0 && Value < 5)
            {
                /* Valid port found, enable Serial Debugging */
                KdpDebugMode.Serial = TRUE;

                /* Set the port to use */
                SerialPortNumber = Value;
            }
        }
        else
        {
            Value = strtoul(p2 + 1, NULL, 0);
            if (Value)
            {
                KdpDebugMode.Serial = TRUE;
                SerialPortInfo.Address = UlongToPtr(Value);
                SerialPortNumber = 0;
            }
        }
    }
    /* Check for File Debugging */
    else if (!_strnicmp(p2, "FILE", 4))
    {
        /* Enable It */
        p2 += 4;
        KdpDebugMode.File = TRUE;
        if (*p2 == ':')
        {
            p2++;
            p1 = p2;
            while (*p2 != '\0' && *p2 != ' ') p2++;
            KdpLogFileName.MaximumLength = KdpLogFileName.Length = p2 - p1;
            KdpLogFileName.Buffer = p1;
        }
    }

    return p2;
}

/* KEYBOARD FUNCTIONS ********************************************************/

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

static unsigned char keyb_layout[2][128] =
{
    "\000\0331234567890-=\177\t"                                        /* 0x00 - 0x0f */
    "qwertyuiop[]\r\000as"                                              /* 0x10 - 0x1f */
    "dfghjkl;'`\000\\zxcv"                                              /* 0x20 - 0x2f */
    "bnm,./\000*\000 \000\201\202\203\204\205"                          /* 0x30 - 0x3f */
    "\206\207\210\211\212\000\000789-456+1"                             /* 0x40 - 0x4f */
    "230\177\000\000\213\214\000\000\000\000\000\000\000\000\000\000"   /* 0x50 - 0x5f */
    "\r\000/"                                                           /* 0x60 - 0x6f */
    ,
    "\000\033!@#$%^&*()_+\177\t"                                        /* 0x00 - 0x0f */
    "QWERTYUIOP{}\r\000AS"                                              /* 0x10 - 0x1f */
    "DFGHJKL:\"`\000\\ZXCV"                                             /* 0x20 - 0x2f */
    "BNM<>?\000*\000 \000\201\202\203\204\205"                          /* 0x30 - 0x3f */
    "\206\207\210\211\212\000\000789-456+1"                             /* 0x40 - 0x4f */
    "230\177\000\000\213\214\000\000\000\000\000\000\000\000\000\000"   /* 0x50 - 0x5f */
    "\r\000/"                                                           /* 0x60 - 0x6f */
};

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

static VOID KbdEnableMouse()
{
    KbdSendCommandToMouse(MOU_ENAB);
}

static VOID KbdDisableMouse()
{
    KbdSendCommandToMouse(MOU_DISAB);
}

static CHAR
KdbpTryGetCharKeyboard(PULONG ScanCode, ULONG Retry)
{
    static UCHAR last_key = 0;
    static UCHAR shift = 0;
    char c;
    BOOLEAN KeepRetrying = (Retry == 0);

    while (KeepRetrying || Retry-- > 0)
    {
        while (kbd_read_status() & KBD_STAT_OBF)
        {
            UCHAR scancode;

            scancode = kbd_read_input();

            /* check for SHIFT-keys */
            if (((scancode & 0x7F) == 42) || ((scancode & 0x7F) == 54))
            {
                shift = !(scancode & 0x80);
                continue;
            }

            /* ignore all other RELEASED-codes */
            if (scancode & 0x80)
            {
                last_key = 0;
            }
            else if (last_key != scancode)
            {
                //printf("kbd: %d, %d, %c\n", scancode, last_key, keyb_layout[shift][scancode]);
                last_key = scancode;
                c = keyb_layout[shift][scancode];
                *ScanCode = scancode;

                if (c > 0)
                    return c;
            }
        }
    }

    return -1;
}

/* SCREEN FUNCTIONS **********************************************************/

static VOID
NTAPI
KdpScreenDebugPrint(PCHAR Message,
                    ULONG Length)
{
    PCHAR pch = (PCHAR)Message;

    while (pch < Message + Length && *pch)
    {
        if (*pch == '\b')
        {
            /* HalDisplayString does not support '\b'. Workaround it and use '\r' */
            if (KdpScreenLineLength > 0)
            {
                /* Remove last character from buffer */
                KdpScreenLineBuffer[--KdpScreenLineLength] = '\0';
                KdpScreenLineBufferPos = KdpScreenLineLength;

                /* Clear row and print line again */
                HalDisplayString("\r");
                HalDisplayString(KdpScreenLineBuffer);
            }
        }
        else
        {
            KdpScreenLineBuffer[KdpScreenLineLength++] = *pch;
            KdpScreenLineBuffer[KdpScreenLineLength] = '\0';
        }

        if (*pch == '\n' || KdpScreenLineLength == KdpScreenLineLengthDefault)
        {
            /* Print buffered characters */
            if (KdpScreenLineBufferPos != KdpScreenLineLength)
                HalDisplayString(KdpScreenLineBuffer + KdpScreenLineBufferPos);

            /* Clear line buffer */
            KdpScreenLineBuffer[0] = '\0';
            KdpScreenLineLength = KdpScreenLineBufferPos = 0;
        }

        ++pch;
    }

    /* Print buffered characters */
    if (KdpScreenLineBufferPos != KdpScreenLineLength)
    {
        HalDisplayString(KdpScreenLineBuffer + KdpScreenLineBufferPos);
        KdpScreenLineBufferPos = KdpScreenLineLength;
    }
}

static VOID
KdpScreenAcquire(VOID)
{
    if (InbvIsBootDriverInstalled() /* &&
        !InbvCheckDisplayOwnership() */)
    {
        /* Acquire ownership and reset the display */
        InbvAcquireDisplayOwnership();
        InbvResetDisplay();
        InbvSolidColorFill(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1, BV_COLOR_BLACK);
        InbvSetTextColor(BV_COLOR_WHITE);
        InbvInstallDisplayStringFilter(NULL);
        InbvEnableDisplayString(TRUE);
        InbvSetScrollRegion(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1);
    }
}

static VOID
NTAPI
KdpScreenInit(ULONG BootPhase)
{
    if (!KdpDebugMode.Screen) return;

    if (BootPhase == 0)
    {
    }
    else if (BootPhase == 1)
    {
        /* Take control of the display */
        KdpScreenAcquire();

        HalDisplayString("\r\n   Screen debugging enabled\r\n\r\n");
    }
}

/* SERIAL FUNCTIONS **********************************************************/

static VOID
NTAPI
KdpSerialDebugPrint(PCHAR Message,
                    ULONG Length)
{
    PCHAR pch = (PCHAR)Message;

    /* Output the message */
    while (pch < Message + Length && *pch != '\0')
    {
        if (*pch == '\n')
        {
            CpPutByte(&SerialPortInfo, '\r');
        }
        CpPutByte(&SerialPortInfo, *pch);
        pch++;
    }
}

static BOOLEAN
NTAPI
KdPortInitializeEx(
    IN PCPPORT PortInformation,
    IN ULONG ComPortNumber)
{
    NTSTATUS Status;

    /* Initialize the port */
    Status = CpInitialize(PortInformation,
                          (ComPortNumber == 0 ? PortInformation->Address
                                              : UlongToPtr(BaseArray[ComPortNumber])),
                          (PortInformation->BaudRate == 0 ? DEFAULT_BAUD_RATE
                                                          : PortInformation->BaudRate));
    if (!NT_SUCCESS(Status))
    {
        HalDisplayString("\r\nKernel Debugger: Serial port not found!\r\n\r\n");
        return FALSE;
    }
    else
    {
#ifndef NDEBUG
        CHAR buffer[80];

        /* Print message to blue screen */
        sprintf(buffer,
                "\r\nKernel Debugger: Serial port found: COM%ld (Port 0x%p) BaudRate %ld\r\n\r\n",
                ComPortNumber,
                PortInformation->Address,
                PortInformation->BaudRate);
        HalDisplayString(buffer);
#endif /* NDEBUG */

        return TRUE;
    }
}

static VOID
NTAPI
KdpSerialInit(ULONG BootPhase)
{
    if (!KdpDebugMode.Serial) return;

    if (BootPhase == 0)
    {
        /* Initialize the Port */
        if (!KdPortInitializeEx(&SerialPortInfo, SerialPortNumber))
        {
            KdpDebugMode.Serial = FALSE;
            return;
        }
        KdComPortInUse = SerialPortInfo.Address;
    }
    else if (BootPhase == 1)
    {
        HalDisplayString("\r\n   Serial debugging enabled\r\n\r\n");
    }
}

static CHAR
KdbpTryGetCharSerial(ULONG Retry)
{
    CHAR Result = -1;

    if (Retry == 0)
        while (CpGetByte(&SerialPortInfo, (PUCHAR)&Result, FALSE, FALSE) != CP_GET_SUCCESS);
    else
        while (CpGetByte(&SerialPortInfo, (PUCHAR)&Result, FALSE, FALSE) != CP_GET_SUCCESS && Retry-- > 0);

    return Result;
}

/* FILE FUNCTIONS **********************************************************/

static VOID
NTAPI
KdpFileInit(ULONG BootPhase);

static VOID
NTAPI
KdpLoggerThread(PVOID Context)
{
    ULONG beg, end, num;
    IO_STATUS_BLOCK Iosb;

    ASSERT(ExGetPreviousMode() == KernelMode);

    while (TRUE)
    {
        KeWaitForSingleObject(&KdpLoggerThreadEvent, Executive, KernelMode, FALSE, NULL);

        /* Bug */
        /* Keep KdpCurrentPosition and KdpFreeBytes values in local
         * variables to avoid their possible change from Producer part,
         * KdpPrintToLogFile function
         */
        end = KdpCurrentPosition;
        num = KdpFreeBytes;

        /* Now securely calculate values, based on local variables */
        beg = (end + num) % KdpBufferSize;
        num = KdpBufferSize - num;

        /* Nothing to do? */
        if (num == 0)
            continue;

        if (end > beg)
        {
            NtWriteFile(KdpLogFileHandle, NULL, NULL, NULL, &Iosb,
                        KdpDebugBuffer + beg, num, NULL, NULL);
        }
        else
        {
            NtWriteFile(KdpLogFileHandle, NULL, NULL, NULL, &Iosb,
                        KdpDebugBuffer + beg, KdpBufferSize - beg, NULL, NULL);

            NtWriteFile(KdpLogFileHandle, NULL, NULL, NULL, &Iosb,
                        KdpDebugBuffer, end, NULL, NULL);
        }

        (VOID)InterlockedExchangeAdd((LONG*)&KdpFreeBytes, num);
    }
}

static VOID
NTAPI
KdpFileDebugPrint(PCHAR Message,
                  ULONG Length)

{
    ULONG beg, end, num;

    if (KdpDebugBuffer == NULL)
        return;

    if (!KdpLogFileHandle)
    {
        KIRQL OldIrql = KeGetCurrentIrql();
        KeLowerIrql(PASSIVE_LEVEL);
        KdpFileInit(3);
        KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    }

    beg = KdpCurrentPosition;
    num = KdpFreeBytes;
    if (Length < num)
        num = Length;

    if (num != 0)
    {
        end = (beg + num) % KdpBufferSize;
        KdpCurrentPosition = end;
        KdpFreeBytes -= num;

        if (end > beg)
        {
            RtlCopyMemory(KdpDebugBuffer + beg, Message, num);
        }
        else
        {
            RtlCopyMemory(KdpDebugBuffer + beg, Message, KdpBufferSize - beg);
            RtlCopyMemory(KdpDebugBuffer, Message + KdpBufferSize - beg, end);
        }
    }

    /* Signal the logger thread */
    if (KdpLogFileHandle)
        KeSetEvent(&KdpLoggerThreadEvent, IO_NO_INCREMENT, FALSE);
}

static VOID
NTAPI
KdpFileInit(ULONG BootPhase)
{
    NTSTATUS Status;
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE ThreadHandle;
    KPRIORITY Priority;
    ULONG BufferSize = 512 * 1024;
    PCHAR DebugBuffer;

    if (!KdpDebugMode.File) return;

    if (BootPhase == 0)
    {
        KdpDebugBuffer = KdpDebugBufferStatic;
        KdpFreeBytes = KdpBufferSize = sizeof(KdpDebugBufferStatic);
    }
    else if (BootPhase == 1)
    {
        /* Allocate a buffer for debug log */
        DebugBuffer = ExAllocatePool(NonPagedPool, BufferSize);
        if (DebugBuffer)
        {
            RtlCopyMemory(DebugBuffer, KdpDebugBuffer, KdpBufferSize - KdpFreeBytes);
            KdpDebugBuffer = DebugBuffer;
            KdpFreeBytes += BufferSize - KdpBufferSize;
            KdpBufferSize = BufferSize;
        }

        /* Initialize spinlock */
        KeInitializeSpinLock(&KdpDebugLogSpinLock);

        HalDisplayString("\r\n   File log debugging enabled\r\n\r\n");
    }
    else if (BootPhase == 3 && KdpDebugBuffer != KdpDebugBufferStatic)
    {
        /* Setup the log name */
        Status = RtlAnsiStringToUnicodeString(&FileName, &KdpLogFileName, TRUE);
        if (!NT_SUCCESS(Status)) return;

        InitializeObjectAttributes(&ObjectAttributes,
                                   &FileName,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL,
                                   NULL);

        /* Create the log file */
        Status = ZwCreateFile(&KdpLogFileHandle,
                              FILE_APPEND_DATA | SYNCHRONIZE,
                              &ObjectAttributes,
                              &Iosb,
                              NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ,
                              FILE_SUPERSEDE,
                              FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT,
                              NULL,
                              0);

        RtlFreeUnicodeString(&FileName);

        if (!NT_SUCCESS(Status))
        {
            KdpLogFileHandle = NULL;
            return;
        }

        KeInitializeEvent(&KdpLoggerThreadEvent, SynchronizationEvent, TRUE);

        /* Create the logger thread */
        Status = PsCreateSystemThread(&ThreadHandle,
                                      THREAD_ALL_ACCESS,
                                      NULL,
                                      NULL,
                                      NULL,
                                      KdpLoggerThread,
                                      NULL);
        if (!NT_SUCCESS(Status))
        {
            ZwClose(KdpLogFileHandle);
            KdpLogFileHandle = NULL;
            return;
        }

        Priority = 7;
        ZwSetInformationThread(ThreadHandle,
                               ThreadPriority,
                               &Priority,
                               sizeof(Priority));

        ZwClose(ThreadHandle);
    }
}

VOID
KdpPrintString(
    _In_ PSTRING Output)
{
    if (KdpDebugMode.Screen)
        KdpScreenDebugPrint(Output->Buffer, Output->Length);
    if (KdpDebugMode.Serial)
        KdpSerialDebugPrint(Output->Buffer, Output->Length);
    if (KdpDebugMode.File)
        KdpFileDebugPrint(Output->Buffer, Output->Length);
}

/* FUNCTIONS ****************************************************************/

CHAR
KdpTryGetChar(
    _Out_ PULONG ScanCode,
    _In_ ULONG Retry)
{
    CHAR Response;

    /* Check if this is serial debugging mode */
    if (KdbDebugState & KD_DEBUG_KDSERIAL)
    {
        /* Get the character from serial */
        *ScanCode = 0;
        Response = KdbpTryGetCharSerial(Retry);
        if (Response == KEY_ESC)
        {
            do
            {
                Response = KdbpTryGetCharSerial(MAXULONG);
            } while (Response == -1);
            if (Response == '[')
            {
                do
                {
                    Response = KdbpTryGetCharSerial(MAXULONG);
                } while (Response == -1);
                switch (Response)
                {
                    case 'A': *ScanCode = KEY_SCAN_UP; break;
                    case 'B': *ScanCode = KEY_SCAN_DOWN; break;
                    default: break;
                }
            }
        }
        return Response;
    }
    else
    {
        /* Get the response from the keyboard */
        return KdbpTryGetCharKeyboard(ScanCode, Retry);
    }
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
KdDebuggerInitialize0(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock OPTIONAL)
{
    PCHAR CommandLine, Port = NULL;

    if (LoaderBlock)
    {
        /* Check if we have a command line */
        CommandLine = LoaderBlock->LoadOptions;
        if (CommandLine)
        {
            /* Upcase it */
            _strupr(CommandLine);

            /* Get the KDBG Settings */
            KdbpGetCommandLineSettings(CommandLine);

            /* Get the port */
            Port = strstr(CommandLine, "DEBUGPORT");
        }
    }

    /* Check if we got the /DEBUGPORT parameter(s) */
    while (Port)
    {
        /* Move past the actual string, to reach the port*/
        Port += sizeof("DEBUGPORT") - 1;

        /* Now get past any spaces and skip the equal sign */
        while (*Port == ' ') Port++;
        Port++;

        /* Get the debug mode and wrapper */
        Port = KdpGetDebugMode(Port);
        Port = strstr(Port, "DEBUGPORT");
    }

    /* Use serial port then */
    if (KdpDebugMode.Value == 0)
        KdpDebugMode.Serial = TRUE;

    /* Call Providers at Phase 0 */
    if (KdpDebugMode.Screen)
        KdpScreenInit(0);
    if (KdpDebugMode.Serial)
        KdpSerialInit(0);
    if (KdpDebugMode.File)
        KdpFileInit(0);

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
KdDebuggerInitialize1(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock OPTIONAL)
{
    /* Call the registered handlers */
    if (KdpDebugMode.Screen)
        KdpScreenInit(1);
    if (KdpDebugMode.Serial)
        KdpSerialInit(1);
    if (KdpDebugMode.File)
        KdpFileInit(1);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdD0Transition(VOID)
{
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdD3Transition(VOID)
{
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
KdSave(
    IN BOOLEAN SleepTransition)
{
    /* Nothing to do on COM ports */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
KdRestore(
    IN BOOLEAN SleepTransition)
{
    /* Nothing to do on COM ports */
    return STATUS_SUCCESS;
}

/*
 * @unimplemented
 */
VOID
NTAPI
KdSendPacket(
    IN ULONG PacketType,
    IN PSTRING MessageHeader,
    IN PSTRING MessageData,
    IN OUT PKD_CONTEXT Context)
{
    if (PacketType == PACKET_TYPE_KD_DEBUG_IO)
    {
        KdpPrintString(MessageData);
        return;
    }
}

/*
 * @implemented
 */
KDSTATUS
NTAPI
KdReceivePacket(
    IN ULONG PacketType,
    OUT PSTRING MessageHeader,
    OUT PSTRING MessageData,
    OUT PULONG DataLength,
    IN OUT PKD_CONTEXT Context)
{
    STRING StringChar;
    CHAR Response;
    CHAR MessageBuffer[100];
    STRING ResponseString;

#ifndef KDBG
    if (PacketType == PACKET_TYPE_KD_STATE_MANIPULATE)
    {
        /* Let's say that everything went fine every time. */
        PDBGKD_MANIPULATE_STATE64 ManipulateState = (PDBGKD_MANIPULATE_STATE64)MessageHeader->Buffer;
        RtlZeroMemory(MessageHeader->Buffer, MessageHeader->MaximumLength);
        ManipulateState->ApiNumber = DbgKdContinueApi;
        ManipulateState->u.Continue.ContinueStatus = STATUS_SUCCESS;
        MessageHeader->Length = sizeof(*ManipulateState);
        return KdPacketReceived;
    }
#endif
    if (PacketType == PACKET_TYPE_KD_DEBUG_IO)
    {
        ResponseString.Buffer = MessageBuffer;
        ResponseString.Length = 0;
        ResponseString.MaximumLength = min(sizeof(MessageBuffer), MessageData->MaximumLength);
        StringChar.Buffer = &Response;
        StringChar.Length = StringChar.MaximumLength = sizeof(Response);

        /* Display the string and print a new line for log neatness */
        *StringChar.Buffer = '\n';
        KdpPrintString(&StringChar);

        /* Print the kdb prompt */
        KdpPrintString(&KdbPromptString);

        if (!(KdbDebugState & KD_DEBUG_KDSERIAL))
            KbdDisableMouse();

        /* Read response */
        KdpReadCommand(&ResponseString);
        KdpCommandHistoryAppend(ResponseString.Buffer);

        /* Print a new line */
        *StringChar.Buffer = '\n';
        KdpPrintString(&StringChar);

        /* Return the length */
        RtlCopyMemory(MessageData->Buffer, ResponseString.Buffer, ResponseString.Length);
        *DataLength = ResponseString.Length;

        if (!(KdbDebugState & KD_DEBUG_KDSERIAL))
            KbdEnableMouse();

        return KdPacketReceived;
    }

    return KdPacketTimedOut;
}

/* EOF */
