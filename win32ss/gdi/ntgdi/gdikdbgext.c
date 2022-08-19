/*
 * PROJECT:         ReactOS win32 kernel mode subsystem
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            win32ss/gdi/ntgdi/gdikdbgext.c
 * PURPOSE:         KDBG extension for GDI
 * PROGRAMMERS:     Timo Kreuzer
 */

/* INCLUDES ******************************************************************/

#include <win32k.h>
//#define NDEBUG
//#include <debug.h>
#include <wdbgexts.h>

extern PENTRY gpentHmgr;
extern PULONG gpaulRefCount;
extern ULONG gulFirstUnused;
WINDBG_EXTENSION_APIS ExtensionApis;

static const char * gpszObjectTypes[] =
{
    "FREE", "DC", "UNUSED1", "UNUSED2", "RGN", "SURF", "CLIENTOBJ", "PATH",
    "PAL", "ICMLCS", "LFONT", "RFONT", "PFE", "PFT", "ICMCXF", "SPRITE",
    "BRUSH", "UMPD", "UNUSED4", "SPACE", "UNUSED5", "META", "EFSTATE",
    "BMFD", "VTFD", "TTFD", "RC", "TEMP", "DRVOBJ", "DCIOBJ", "SPOOL",
    "RESERVED", "ALL"
};


BOOLEAN
KdbIsMemoryValid(PVOID pvBase, ULONG cjSize)
{
    PUCHAR pjAddress;

    pjAddress = ALIGN_DOWN_POINTER_BY(pvBase, PAGE_SIZE);

    while (pjAddress < (PUCHAR)pvBase + cjSize)
    {
        if (!MmIsAddressValid(pjAddress)) return FALSE;
        pjAddress += PAGE_SIZE;
    }

    return TRUE;
}

static
BOOL
KdbGetHexNumber(char *pszNum, ULONG_PTR *pulValue)
{
    char *endptr;

    /* Skip optional '0x' prefix */
    if ((pszNum[0] == '0') && ((pszNum[1] == 'x') || (pszNum[1] == 'X')))
        pszNum += 2;

    /* Make a number from the string (hex) */
    *pulValue = strtoul(pszNum, &endptr, 16);

    return (*endptr == '\0');
}

static
DECLARE_API(KdbCommand_Gdi_help)
{
    dprintf("GDI KDBG extension.\nAvailable commands:\n"
            "- help - Displays this screen.\n"
            "- dumpht [<type>] - Dumps all handles of <type> or lists all types\n"
            "- handle <handle> - Displays information about a handle\n"
            "- entry <entry> - Displays an ENTRY, <entry> can be a pointer or index\n"
#if DBG_ENABLE_EVENT_LOGGING
            "- eventlist <object> - Displays the eventlist for an object\n"
#endif
            );
}

static
DECLARE_API(KdbCommand_Gdi_dumpht)
{
    ULONG i;
    UCHAR Objt, jReqestedType;
    PENTRY pentry;
    POBJ pobj;
    KAPC_STATE ApcState;
    ULONG_PTR ulArg;

    /* No CSRSS, no handle table */
    if (!gpepCSRSS) return;
    KeStackAttachProcess(&gpepCSRSS->Pcb, &ApcState);

    if (*args == 0)
    {
        USHORT Counts[GDIObjType_MAX_TYPE + 2] = {0};

        /* Loop all possibly used entries in the handle table */
        for (i = RESERVE_ENTRIES_COUNT; i < gulFirstUnused; i++)
        {
            if (KdbIsMemoryValid(&gpentHmgr[i], sizeof(ENTRY)))
            {
                Objt = gpentHmgr[i].Objt & 0x1F;
                Counts[Objt]++;
            }
        }

        dprintf("Type         Count\n");
        dprintf("-------------------\n");
        for (i = 0; i <= GDIObjType_MAX_TYPE; i++)
        {
            dprintf("%02x %-9s %d\n",
                     i, gpszObjectTypes[i], Counts[i]);
        }
        dprintf("\n");
    }
    else
    {
        /* Loop all object types */
        for (i = 0; i <= GDIObjType_MAX_TYPE + 1; i++)
        {
            /* Check if this object type was requested */
            if (stricmp(args, gpszObjectTypes[i]) == 0) break;
        }

        /* Check if we didn't find it yet */
        if (i > GDIObjType_MAX_TYPE + 1)
        {
            /* Try if it's a number */
            if (!KdbGetHexNumber((char*)args, &ulArg))
            {
                dprintf("Invalid parameter: %s\n", args);
                return;
            }

            /* Check if it's inside the allowed range */
            if (i > GDIObjType_MAX_TYPE)
            {
                dprintf("Unknown object type: %s\n", args);
                goto leave;
            }
        }

        jReqestedType = i;

        /* Print header */
        dprintf("Index Handle   Type      pObject    ThreadId cLocks  ulRefCount\n");
        dprintf("---------------------------------------------------------------\n");

        /* Loop all possibly used entries in the handle table */
        for (i = RESERVE_ENTRIES_COUNT; i < gulFirstUnused; i++)
        {
            /* Get the entry and the object */
            pentry = &gpentHmgr[i];

            if (!MmIsAddressValid(pentry)) continue;

            pobj = pentry->einfo.pobj;
            Objt = pentry->Objt & 0x1F;

            /* Check if ALL objects are requested, or the object type matches */
            if ((jReqestedType == GDIObjType_MAX_TYPE + 1) ||
                (Objt == jReqestedType))
            {
                dprintf("%04lx  %p %-9s 0x%p 0x%06lx %-6ld ",
                         i, pobj->hHmgr, gpszObjectTypes[Objt], pobj,
                         pobj->dwThreadId, pobj->cExclusiveLock);
                if (MmIsAddressValid(&gpaulRefCount[i]))
                    dprintf("0x%08lx\n", gpaulRefCount[i]);
                else
                    dprintf("??????????\n");
            }
        }
    }

leave:
    KeUnstackDetachProcess(&ApcState);
}

static
DECLARE_API(KdbCommand_Gdi_handle)
{
    ULONG_PTR ulObject;
    BASEOBJECT *pobj;
    ENTRY *pentry;
    USHORT usIndex;
    KAPC_STATE ApcState;

    /* Convert the parameter into a number */
    if (!KdbGetHexNumber((char*)args, &ulObject))
    {
        dprintf("Invalid parameter: %s\n", args);
        return;
    }

    /* No CSRSS, no handle table */
    if (!gpepCSRSS) return;
    KeStackAttachProcess(&gpepCSRSS->Pcb, &ApcState);

    usIndex = ulObject & 0xFFFF;
    pentry = &gpentHmgr[usIndex];

    if (MmIsAddressValid(pentry))
    {
        pobj = pentry->einfo.pobj;

        dprintf("GDI handle=%p, type=%s, index=0x%lx, pentry=%p.\n",
                 ulObject, gpszObjectTypes[(ulObject >> 16) & 0x1f],
                 usIndex, pentry);
        dprintf(" ENTRY = {.pobj = %p, ObjectOwner = 0x%lx, FullUnique = 0x%04x,\n"
                 "  Objt=0x%02x, Flags = 0x%02x, pUser = 0x%p}\n",
                 pentry->einfo.pobj, pentry->ObjectOwner.ulObj, pentry->FullUnique,
                 pentry->Objt, pentry->Flags, pentry->pUser);
        dprintf(" BASEOBJECT = {hHmgr = %p, dwThreadId = 0x%lx,\n"
                 "  cExclusiveLock = %ld, BaseFlags = 0x%lx}\n",
                 pobj->hHmgr, pobj->dwThreadId,
                 pobj->cExclusiveLock, pobj->BaseFlags);
        if (MmIsAddressValid(&gpaulRefCount[usIndex]))
            dprintf(" gpaulRefCount[idx] = %ld\n", gpaulRefCount[usIndex]);
    }
    else
    {
        dprintf("Coudn't access ENTRY. Probably paged out.\n");
    }

    KeUnstackDetachProcess(&ApcState);
}

static
DECLARE_API(KdbCommand_Gdi_entry)
{
    ULONG_PTR ulValue;
    PENTRY pentry;
    KAPC_STATE ApcState;

    /* Convert the parameter into a number */
    if (!KdbGetHexNumber((char*)args, &ulValue))
    {
        dprintf("Invalid parameter: %s\n", args);
        return;
    }

    /* No CSRSS, no handle table */
    if (!gpepCSRSS) return;
    KeStackAttachProcess(&gpepCSRSS->Pcb, &ApcState);

    /* If the parameter is smaller than 0x10000, it's an index */
    pentry = (ulValue <= 0xFFFF) ? &gpentHmgr[ulValue] : (PENTRY)ulValue;

    /* Check if the address is readable */
    if (!MmIsAddressValid(pentry))
    {
        dprintf("Cannot access entry at %p\n", pentry);
        goto cleanup;
    }

    /* print the entry */
    dprintf("Dumping ENTRY #%ld, @%p:\n", (pentry - gpentHmgr), pentry);
    if (pentry->Objt != 0)
        dprintf(" pobj = 0x%p\n", pentry->einfo.pobj);
    else
        dprintf(" hFree = 0x%p\n", pentry->einfo.hFree);
    dprintf(" ObjectOwner = 0x%p\n", pentry->ObjectOwner.ulObj);
    dprintf(" FullUnique = 0x%x\n", pentry->FullUnique);
    dprintf(" Objt = 0x%x (%s)\n", pentry->Objt,
             pentry->Objt <= 0x1E ? gpszObjectTypes[pentry->Objt] : "invalid");
    dprintf(" Flags = 0x%x\n", pentry->Flags);
    dprintf(" pUser = 0x%p\n", pentry->pUser);

cleanup:
    KeUnstackDetachProcess(&ApcState);
}

#if DBG_ENABLE_EVENT_LOGGING
static
DECLARE_API(KdbCommand_Gdi_eventlist)
{
    ULONG_PTR ulValue;
    POBJ pobj;
    PSLIST_ENTRY psle, psleFirst;
    PLOGENTRY pLogEntry;

    /* Convert the parameter into a number */
    if (!KdbGetHexNumber(args, &ulValue))
    {
        dprintf("Invalid parameter: %s\n", args);
        return;
    }

    pobj = (POBJ)ulValue;

    /* Check if the address is readable */
    if (!KdbIsMemoryValid(pobj, sizeof(BASEOBJECT)))
    {
        dprintf("Cannot access BASEOBJECT at %p\n", pobj);
        return;
    }

    /* The kernel doesn't export RtlFirstEntrySList :( */
    psleFirst = InterlockedFlushSList(&pobj->slhLog);

    /* Loop all events, but don't remove them */
    for (psle = psleFirst; psle != NULL; psle = psle->Next)
    {
        pLogEntry = CONTAINING_RECORD(psle, LOGENTRY, sleLink);
        dprintfEvent(pLogEntry);
    }

    /* Put the log back in place */
    InterlockedPushEntrySList(&pobj->slhLog, psleFirst);
}
#endif

static
VOID
NTAPI
KdbCommand_Gdi_init(
    _In_ PWINDBG_EXTENSION_APIS lpExtensionApis,
    _In_ USHORT usMajorVersion,
    _In_ USHORT usMinorVersion)
{
    ExtensionApis = *lpExtensionApis;
}

KDBG_CLI_REGISTRATION DbgGdiKdbgCliRegistration = {
    KdbCommand_Gdi_init,
    {
        { "!gdi.help", "!gdi.help", "Display list of available !gdi commands.", KdbCommand_Gdi_help },
        { "!gdi.dumpht", "!gdi.dumpht [type]", "Dumps all handles of 'type' or lists all types", KdbCommand_Gdi_dumpht },
        { "!gdi.handle", "!gdi.handle HANDLE", "Displays information about a handle.", KdbCommand_Gdi_handle },
        { "!gdi.entry", "!gdi.entry Address|Index", "Displays an entry.", KdbCommand_Gdi_entry },
#if DBG_ENABLE_EVENT_LOGGING
        { "!gdi.eventlist", "!gdi.eventlist Address", "Displays the event list for an object", KdbCommand_Gdi_eventlist },
#endif
        {}
    }
};

