/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     Test for NtUserGetKeyboardLayoutName
 * COPYRIGHT:   Copyright 2022 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
 */

#include <win32nt.h>
#include <pseh/pseh2.h>

typedef BOOL (APIENTRY *FN_NtUserGetKeyboardLayoutName)(PVOID);

START_TEST(NtUserGetKeyboardLayoutName)
{
    FN_NtUserGetKeyboardLayoutName fn = (FN_NtUserGetKeyboardLayoutName)NtUserGetKeyboardLayoutName;
    UNICODE_STRING ustr;
    WCHAR szBuff[MAX_PATH];
    PVOID pvAllocation;
    BOOL ret;

    /* Try NULL */
    ok_int(fn(NULL), FALSE);

    /* Try szBuff */
    RtlZeroMemory(szBuff, sizeof(szBuff));
    ret = fn(szBuff);

    //ok_int(ret, FALSE); // XP:TRUE, 2k3:FALSE
    ok(szBuff[0] == 0, "szBuff[0] was %d\n", szBuff[0]);

    /* Try ustr */
    RtlZeroMemory(szBuff, sizeof(szBuff));
    ustr.Buffer = szBuff;
    ustr.Length = 0;
    ustr.MaximumLength = RTL_NUMBER_OF(szBuff) * sizeof(WCHAR);
    ret = fn(&ustr);

    ok_int(ret, TRUE);
    ok_int(ustr.Length, 0);
    ok(szBuff[0] != 0, "szBuff[0] was %d\n", szBuff[0]);
    trace("szBuff: %S\n", szBuff);

    /* Try invalid buffer */
    ustr.Buffer = (PWCHAR)(LONG_PTR)-1;
    ustr.Length = 0;
    ustr.MaximumLength = RTL_NUMBER_OF(szBuff) * sizeof(WCHAR);
    ret = fn(&ustr);
    ok_int(ret, FALSE);
    ok_int(GetLastError(), ERROR_NOACCESS);

    /* Try too small buffer */
    RtlZeroMemory(szBuff, sizeof(szBuff));
    ustr.Buffer = szBuff;
    ustr.Length = 0;
    ustr.MaximumLength = 2;
    ret = fn(&ustr);
    ok_int(ret, FALSE);
    ok(szBuff[0] == 0, "szBuff[0] was %d\n", szBuff[0]);
    ok_int(GetLastError(), ERROR_INVALID_PARAMETER);

    pvAllocation = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
    ok(pvAllocation != NULL, "VirtualAlloc failed with error %d\n", GetLastError());
    if (pvAllocation != NULL)
    {
        /* Try invalid buffer */
        ustr.Buffer = (PWCHAR)pvAllocation;
        ustr.Length = 0;
        ustr.MaximumLength = PAGE_SIZE + 1;
        ret = fn(&ustr);
        ok_int(ret, FALSE);
        ok(ustr.Buffer[0] == 0, "ustr.Buffer[0] was %d\n", szBuff[0]);
        ok_int(GetLastError(), ERROR_NOACCESS);
        VirtualFree(pvAllocation, 0, MEM_RELEASE);
    }

}
