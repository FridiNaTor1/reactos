#include "kdrosdbg.h"

static CHAR KdbCommandHistoryBuffer[2048]; /* Command history string ringbuffer */
static PCHAR KdbCommandHistory[sizeof(KdbCommandHistoryBuffer) / 8] = { NULL }; /* Command history ringbuffer */
static LONG KdbCommandHistoryBufferIndex = 0;
static LONG KdbCommandHistoryIndex = 0;

/*!\brief Appends a command to the command history
 *
 * \param Command  Pointer to the command to append to the history.
 */
VOID
KdpCommandHistoryAppend(
    IN PCHAR Command)
{
    SIZE_T Length1 = strlen(Command) + 1;
    SIZE_T Length2 = 0;
    INT i;
    PCHAR Buffer;

    ASSERT(Length1 <= RTL_NUMBER_OF(KdbCommandHistoryBuffer));

    if (Length1 <= 1 ||
        (KdbCommandHistory[KdbCommandHistoryIndex] &&
         strcmp(KdbCommandHistory[KdbCommandHistoryIndex], Command) == 0))
    {
        return;
    }

    /* Calculate Length1 and Length2 */
    Buffer = KdbCommandHistoryBuffer + KdbCommandHistoryBufferIndex;
    KdbCommandHistoryBufferIndex += Length1;
    if (KdbCommandHistoryBufferIndex >= (LONG)RTL_NUMBER_OF(KdbCommandHistoryBuffer))
    {
        KdbCommandHistoryBufferIndex -= RTL_NUMBER_OF(KdbCommandHistoryBuffer);
        Length2 = KdbCommandHistoryBufferIndex;
        Length1 -= Length2;
    }

    /* Remove previous commands until there is enough space to append the new command */
    for (i = KdbCommandHistoryIndex; KdbCommandHistory[i];)
    {
        if ((Length2 > 0 &&
            (KdbCommandHistory[i] >= Buffer ||
             KdbCommandHistory[i] < (KdbCommandHistoryBuffer + KdbCommandHistoryBufferIndex))) ||
            (Length2 <= 0 &&
             (KdbCommandHistory[i] >= Buffer &&
              KdbCommandHistory[i] < (KdbCommandHistoryBuffer + KdbCommandHistoryBufferIndex))))
        {
            KdbCommandHistory[i] = NULL;
        }

        i--;
        if (i < 0)
            i = RTL_NUMBER_OF(KdbCommandHistory) - 1;

        if (i == KdbCommandHistoryIndex)
            break;
    }

    /* Make sure the new command history entry is free */
    KdbCommandHistoryIndex++;
    KdbCommandHistoryIndex %= RTL_NUMBER_OF(KdbCommandHistory);
    if (KdbCommandHistory[KdbCommandHistoryIndex])
    {
        KdbCommandHistory[KdbCommandHistoryIndex] = NULL;
    }

    /* Append command */
    KdbCommandHistory[KdbCommandHistoryIndex] = Buffer;
    ASSERT((KdbCommandHistory[KdbCommandHistoryIndex] + Length1) <= KdbCommandHistoryBuffer + RTL_NUMBER_OF(KdbCommandHistoryBuffer));
    memcpy(KdbCommandHistory[KdbCommandHistoryIndex], Command, Length1);
    if (Length2 > 0)
    {
        memcpy(KdbCommandHistoryBuffer, Command + Length1, Length2);
    }
}

VOID
KdpReadCommand(
    _Inout_ PSTRING ResponseString)
{
    STRING StringChar;
    CHAR Response;
    ULONG ScanCode = 0;
    BOOLEAN EchoOn = !((KdbDebugState & KD_DEBUG_KDNOECHO) != 0);
    INT CmdHistIndex = -1;
    INT_PTR i;

    StringChar.Buffer = &Response;
    StringChar.Length = StringChar.MaximumLength = sizeof(Response);

    /* Loop the whole string */
    while (ResponseString->Length < ResponseString->MaximumLength)
    {
        do
        {
            Response = KdpTryGetChar(&ScanCode, MAXULONG);
        } while (Response == -1);

        /* Check for return */
        if (Response == '\r')
        {
            /*
             * We might need to discard the next '\n'.
             * Wait a bit to make sure we receive it.
             */
            KeStallExecutionProcessor(100000);

            /* Read and discard the next character, if any */
            KdpTryGetChar(&ScanCode, 5);

            /*
             * Null terminate the output string -- documentation states that
             * DbgPrompt does not null terminate, but it does
             */
            ResponseString->Buffer[ResponseString->Length] = '\0';
            break;
        }
        else if (Response == KEY_BS || Response == KEY_DEL)
        {
            if (ResponseString->Length > 0)
            {
                if (EchoOn)
                {
                    Response = KEY_BS;
                    KdpPrintString(&StringChar);
                }
                Response = ' ';
                KdpPrintString(&StringChar);
                Response = KEY_BS;
                KdpPrintString(&StringChar);
                ResponseString->Length--;
            }
        }
        else if (ScanCode == KEY_SCAN_UP)
        {
            BOOLEAN Print = TRUE;

            if (CmdHistIndex < 0)
            {
                CmdHistIndex = KdbCommandHistoryIndex;
            }
            else
            {
                i = CmdHistIndex - 1;

                if (i < 0)
                    CmdHistIndex = RTL_NUMBER_OF(KdbCommandHistory) - 1;

                if (KdbCommandHistory[i] && i != KdbCommandHistoryIndex)
                    CmdHistIndex = i;
                else
                    Print = FALSE;
            }

            if (Print && KdbCommandHistory[CmdHistIndex])
            {
                while (ResponseString->Length > 0)
                {
                    if (EchoOn)
                    {
                        Response = KEY_BS;
                        KdpPrintString(&StringChar);
                    }
                    Response = ' ';
                    KdpPrintString(&StringChar);
                    Response = KEY_BS;
                    KdpPrintString(&StringChar);
                    ResponseString->Length--;
                }

                ResponseString->Length = min(strlen(KdbCommandHistory[CmdHistIndex]), ResponseString->MaximumLength);
                memcpy(ResponseString->Buffer, KdbCommandHistory[CmdHistIndex], ResponseString->Length);
                KdpPrintString(ResponseString);
            }
        }
        else if (ScanCode == KEY_SCAN_DOWN)
        {
            if (CmdHistIndex > 0 && CmdHistIndex != KdbCommandHistoryIndex)
            {
                i = CmdHistIndex + 1;
                if (i >= (INT)RTL_NUMBER_OF(KdbCommandHistory))
                    i = 0;

                if (KdbCommandHistory[i])
                {
                    CmdHistIndex = i;
                    while (ResponseString->Length > 0)
                    {
                        if (EchoOn)
                        {
                            Response = KEY_BS;
                            KdpPrintString(&StringChar);
                        }
                        Response = ' ';
                        KdpPrintString(&StringChar);
                        Response = KEY_BS;
                        KdpPrintString(&StringChar);
                        ResponseString->Length--;
                    }

                    ResponseString->Length = min(strlen(KdbCommandHistory[CmdHistIndex]), ResponseString->MaximumLength);
                    memcpy(ResponseString->Buffer, KdbCommandHistory[CmdHistIndex], ResponseString->Length);
                    KdpPrintString(ResponseString);
                }
            }
        }
        else
        {
            /* Write it back and print it to the log */
            ResponseString->Buffer[ResponseString->Length++] = Response;
            if (EchoOn)
                KdpPrintString(&StringChar);
        }
    }
}
