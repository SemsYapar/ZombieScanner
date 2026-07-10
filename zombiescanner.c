// zombiescan.c - Windows zombie process live monitor.
//
// A zombie process: exited, but still referenced by an open HANDLE
// somewhere, so its EPROCESS object survives with no
// address space/handle table of its own.

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#pragma comment(lib, "ntdll.lib")

#define REFRESH_INTERVAL_MS 2000

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// Undocumented SystemInformationClass values.
#define SystemExtendedHandleInformation 64
#define SystemProcessIdInformation      88

// SystemProcessIdInformation: PID in, image name out. Resolves the
// name via a different kernel path than ProcessImageFileName, so it
// can still work for a zombie whose Section object is already gone.
typedef struct _SYSTEM_PROCESS_ID_INFORMATION {
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID  Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG  GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG  HandleAttributes;
    ULONG  Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

extern NTSTATUS NTAPI NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// One (zombie, maker) handle: ownerPid holds ownerHandleValue (a
// value meaningful only inside ownerPid's own handle table) which
// refers to zombiePid's EPROCESS.
typedef struct _ZOMBIE_HANDLE_RECORD {
    DWORD     zombiePid;
    char      zombieName[MAX_PATH];
    DWORD     ownerPid;
    char      ownerName[MAX_PATH];
    ULONG_PTR ownerHandleValue;
} ZOMBIE_HANDLE_RECORD;

static BOOL EnableDebugPrivilege(void)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && (err != ERROR_NOT_ALL_ASSIGNED);
}

// Resolves the "Process" ObjectTypeIndex empirically: looks up a
// handle we KNOW is a Process handle inside the dump instead of
// parsing ObjectTypesInformation (whose layout varies by build).
// selfHandle must be opened BEFORE handleInfo is captured - the dump
// is a snapshot, so a handle opened after it can't be found in it.
static int ResolveProcessObjectTypeIndexFromDump(PSYSTEM_HANDLE_INFORMATION_EX handleInfo,
    HANDLE selfHandle)
{
    DWORD selfPid = GetCurrentProcessId();

    int foundIndex = -1;
    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* e = &handleInfo->Handles[i];
        if ((DWORD)e->UniqueProcessId == selfPid &&
            (HANDLE)e->HandleValue == selfHandle) {
            foundIndex = (int)e->ObjectTypeIndex;
            break;
        }
    }

    return foundIndex;
}

static DWORD* GetActivePidSet(DWORD* outCount)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { *outCount = 0; return NULL; }

    DWORD cap = 512, count = 0;
    DWORD* arr = (DWORD*)malloc(cap * sizeof(DWORD));

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (count >= cap) {
                cap *= 2;
                arr = (DWORD*)realloc(arr, cap * sizeof(DWORD));
            }
            arr[count++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    *outCount = count;
    return arr;
}

static BOOL PidInSet(DWORD pid, DWORD* set, DWORD count)
{
    for (DWORD i = 0; i < count; i++)
        if (set[i] == pid) return TRUE;
    return FALSE;
}

// PID-based name lookup (works for zombies, unlike handle-based
// QueryFullProcessImageName which needs the Section object).
static BOOL GetProcessNameByPidViaSystemInfo(DWORD pid, char* outName, size_t outNameCch)
{
    WCHAR wbuf[512];
    SYSTEM_PROCESS_ID_INFORMATION info;
    info.ProcessId = (HANDLE)(ULONG_PTR)pid;
    info.ImageName.Length = 0;
    info.ImageName.MaximumLength = (USHORT)sizeof(wbuf);
    info.ImageName.Buffer = wbuf;

    NTSTATUS status = NtQuerySystemInformation(SystemProcessIdInformation, &info, sizeof(info), NULL);
    if (!NT_SUCCESS(status) || info.ImageName.Length == 0 || !info.ImageName.Buffer)
        return FALSE;

    int wlen = info.ImageName.Length / sizeof(WCHAR);
    WCHAR* p = info.ImageName.Buffer;
    WCHAR* base = p;
    for (int i = 0; i < wlen; i++)
        if (p[i] == L'\\') base = &p[i + 1];
    int baseLen = (int)((p + wlen) - base);

    char narrow[MAX_PATH];
    int n = WideCharToMultiByte(CP_ACP, 0, base, baseLen, narrow, sizeof(narrow) - 1, NULL, NULL);
    if (n <= 0) return FALSE;

    narrow[n] = '\0';
    strcpy_s(outName, outNameCch, narrow);
    return TRUE;
}

// Handle-based name lookup. Only valid for a live process (needs its
// Section object) - used for owners, never for zombies.
static void GetProcessNameFromHandle(HANDLE h, char* outName, size_t outNameCch)
{
    strcpy_s(outName, outNameCch, "<unknown>");
    if (!h) return;

    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(h, 0, path, &size)) {
        char* base = strrchr(path, '\\');
        base = base ? base + 1 : path;
        strcpy_s(outName, outNameCch, base);
    }
}

// Resolves the Process ObjectTypeIndex once - the kernel's object
// type table is built at boot and stays stable for the OS session, so
// this only needs to run once, not on every scan.
static int ResolveProcessTypeIndexOnce(void)
{
    HANDLE selfHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (!selfHandle) return -1;

    ULONG size = 1 << 20;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    NTSTATUS status;

    do {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(size);
        if (!handleInfo) { CloseHandle(selfHandle); return -1; }

        status = NtQuerySystemInformation(SystemExtendedHandleInformation,
            handleInfo, size, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(handleInfo);
            handleInfo = NULL;
            size *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    int procTypeIdx = -1;
    if (NT_SUCCESS(status))
        procTypeIdx = ResolveProcessObjectTypeIndexFromDump(handleInfo, selfHandle);

    CloseHandle(selfHandle);
    free(handleInfo);
    return procTypeIdx;
}

// One full scan pass. Caller must free the returned array.
static ZOMBIE_HANDLE_RECORD* ScanForZombies(int procTypeIdx, DWORD* outRecCount)
{
    *outRecCount = 0;

    DWORD activeCount = 0;
    DWORD* activePids = GetActivePidSet(&activeCount);

    ULONG size = 1 << 20;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    NTSTATUS status;

    do {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(size);
        if (!handleInfo) { free(activePids); return NULL; }

        status = NtQuerySystemInformation(SystemExtendedHandleInformation,
            handleInfo, size, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(handleInfo);
            handleInfo = NULL;
            size *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        free(activePids);
        return NULL;
    }

    ZOMBIE_HANDLE_RECORD* records = NULL;
    DWORD recCount = 0, recCap = 0;

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* e = &handleInfo->Handles[i];

        if (procTypeIdx >= 0 && e->ObjectTypeIndex != (USHORT)procTypeIdx)
            continue;

        DWORD ownerPid = (DWORD)e->UniqueProcessId;

        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, ownerPid);
        if (!hOwner) continue;

        char ownerName[MAX_PATH];
        GetProcessNameFromHandle(hOwner, ownerName, sizeof(ownerName));

        // Request PROCESS_QUERY_LIMITED_INFORMATION explicitly instead
        // of DUPLICATE_SAME_ACCESS. Source handles can carry a very
        // narrow grant (confirmed via Process Explorer: some handles
        // here carry only PROCESS_DUP_HANDLE, 0x40, nothing else).
        // SAME_ACCESS would carry that same narrow grant over, and
        // GetProcessId() below (which needs QUERY_LIMITED_INFORMATION)
        // would silently fail, making the zombie invisible. With
        // SeDebugPrivilege enabled, this request is checked against
        // the object directly rather than limited by the source
        // handle's grant.
        HANDLE dup = NULL;
        BOOL okDup = DuplicateHandle(hOwner, (HANDLE)e->HandleValue,
            GetCurrentProcess(), &dup,
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0);
        CloseHandle(hOwner);
        if (!okDup || !dup) continue;

        DWORD targetPid = GetProcessId(dup);
        CloseHandle(dup);

        if (targetPid != 0 && !PidInSet(targetPid, activePids, activeCount)) {
            char zombieName[MAX_PATH];
            GetProcessNameByPidViaSystemInfo(targetPid, zombieName, sizeof(zombieName));

            if (recCount >= recCap) {
                recCap = recCap ? recCap * 2 : 64;
                records = (ZOMBIE_HANDLE_RECORD*)realloc(records, recCap * sizeof(*records));
            }
            records[recCount].zombiePid = targetPid;
            strcpy_s(records[recCount].zombieName, sizeof(records[recCount].zombieName), zombieName);
            records[recCount].ownerPid = ownerPid;
            strcpy_s(records[recCount].ownerName, sizeof(records[recCount].ownerName), ownerName);
            records[recCount].ownerHandleValue = e->HandleValue;
            recCount++;
        }
    }

    free(handleInfo);
    free(activePids);

    *outRecCount = recCount;
    return records;
}

// Frame is built as lines (not printf'd directly) so it can be
// painted with WriteConsoleOutputCharacterA, which doesn't move the
// cursor - so live refreshes don't fight the user's scroll position.
typedef struct _LINE_BUFFER {
    char** lines;
    DWORD  count;
    DWORD  cap;
} LINE_BUFFER;

static void LineBufferInit(LINE_BUFFER* lb)
{
    lb->lines = NULL;
    lb->count = 0;
    lb->cap = 0;
}

static void LineBufferAddF(LINE_BUFFER* lb, const char* fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (lb->count >= lb->cap) {
        lb->cap = lb->cap ? lb->cap * 2 : 64;
        lb->lines = (char**)realloc(lb->lines, lb->cap * sizeof(char*));
    }
    lb->lines[lb->count] = _strdup(buf);
    lb->count++;
}

static void LineBufferFree(LINE_BUFFER* lb)
{
    for (DWORD i = 0; i < lb->count; i++) free(lb->lines[i]);
    free(lb->lines);
    lb->lines = NULL;
    lb->count = 0;
    lb->cap = 0;
}

static void PrintZombieTable(LINE_BUFFER* lb, ZOMBIE_HANDLE_RECORD* records, DWORD recCount)
{
    if (recCount == 0) {
        LineBufferAddF(lb, "No zombie processes found.");
        return;
    }

    typedef struct _PRINT_ROW {
        char  zombieLabel[MAX_PATH + 16];
        char  ownerLabel[MAX_PATH + 16];
        DWORD handleCount;
    } PRINT_ROW;

    PRINT_ROW* rows = (PRINT_ROW*)malloc(recCount * sizeof(PRINT_ROW));
    DWORD rowCount = 0;

    DWORD* pairZombie = (DWORD*)malloc(recCount * sizeof(DWORD));
    DWORD* pairOwner = (DWORD*)malloc(recCount * sizeof(DWORD));

    DWORD* distinctZombies = (DWORD*)calloc(recCount, sizeof(DWORD));
    DWORD distinctZombieCount = 0;

    // One row per distinct (zombie, maker) pair, with the handle
    // count for that pair.
    for (DWORD i = 0; i < recCount; i++) {
        DWORD zpid = records[i].zombiePid;
        DWORD opid = records[i].ownerPid;

        BOOL seen = FALSE;
        for (DWORD k = 0; k < rowCount; k++) {
            if (pairZombie[k] == zpid && pairOwner[k] == opid) { seen = TRUE; break; }
        }
        if (seen) continue;

        DWORD handleCount = 0;
        for (DWORD j = 0; j < recCount; j++) {
            if (records[j].zombiePid == zpid && records[j].ownerPid == opid)
                handleCount++;
        }

        _snprintf_s(rows[rowCount].zombieLabel, sizeof(rows[rowCount].zombieLabel), _TRUNCATE,
            "%s(%lu)", records[i].zombieName, zpid);
        _snprintf_s(rows[rowCount].ownerLabel, sizeof(rows[rowCount].ownerLabel), _TRUNCATE,
            "%s(%lu)", records[i].ownerName, opid);
        rows[rowCount].handleCount = handleCount;

        pairZombie[rowCount] = zpid;
        pairOwner[rowCount] = opid;
        rowCount++;

        if (!PidInSet(zpid, distinctZombies, distinctZombieCount))
            distinctZombies[distinctZombieCount++] = zpid;
    }

    size_t zombieColWidth = strlen("Zombie Process");
    size_t ownerColWidth = strlen("Zombie Maker");
    for (DWORD i = 0; i < rowCount; i++) {
        size_t zl = strlen(rows[i].zombieLabel);
        size_t ol = strlen(rows[i].ownerLabel);
        if (zl > zombieColWidth) zombieColWidth = zl;
        if (ol > ownerColWidth)  ownerColWidth = ol;
    }

    char header[256];
    _snprintf_s(header, sizeof(header), _TRUNCATE, "%-*s | %-*s | %s",
        (int)zombieColWidth, "Zombie Process",
        (int)ownerColWidth, "Zombie Maker", "Handles");
    LineBufferAddF(lb, "%s", header);

    char sep[256];
    size_t dashLen = zombieColWidth < sizeof(sep) - 1 ? zombieColWidth : sizeof(sep) - 1;
    memset(sep, '-', dashLen);
    sep[dashLen] = '\0';
    strcat_s(sep, sizeof(sep), "-+-");
    char ownerDashes[256];
    size_t ownerDashLen = ownerColWidth < sizeof(ownerDashes) - 1 ? ownerColWidth : sizeof(ownerDashes) - 1;
    memset(ownerDashes, '-', ownerDashLen);
    ownerDashes[ownerDashLen] = '\0';
    strcat_s(sep, sizeof(sep), ownerDashes);
    strcat_s(sep, sizeof(sep), "-+--------");
    LineBufferAddF(lb, "%s", sep);

    for (DWORD i = 0; i < rowCount; i++) {
        LineBufferAddF(lb, "%-*s | %-*s | %lu",
            (int)zombieColWidth, rows[i].zombieLabel,
            (int)ownerColWidth, rows[i].ownerLabel, rows[i].handleCount);
    }

    LineBufferAddF(lb, "");
    LineBufferAddF(lb, "[*] %lu distinct zombie process(es), %lu (zombie, maker) pair(s).",
        distinctZombieCount, rowCount);

    free(rows);
    free(pairZombie);
    free(pairOwner);
    free(distinctZombies);
}

int wmain(void)
{
    if (!EnableDebugPrivilege()) {
        fprintf(stderr, "[!] Could not enable SeDebugPrivilege - run as Administrator.\n");
        Sleep(2000);
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD maxLinesEverDrawn = 0;

    int procTypeIdx = ResolveProcessTypeIndexOnce();

    for (;;) {
        DWORD recCount = 0;
        ZOMBIE_HANDLE_RECORD* records = ScanForZombies(procTypeIdx, &recCount);

        LINE_BUFFER lb;
        LineBufferInit(&lb);

        SYSTEMTIME st;
        GetLocalTime(&st);
        LineBufferAddF(&lb, "Zombie process monitor - refreshing every %d ms - Ctrl+C to stop",
            REFRESH_INTERVAL_MS);
        LineBufferAddF(&lb, "Last scan: %02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        LineBufferAddF(&lb, "");

        PrintZombieTable(&lb, records, recCount);
        free(records);

        // Paint at absolute buffer rows via WriteConsoleOutputCharacterA
        // - never touches the cursor, so it can't drag a scrolled-up
        // viewport back down.
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        SHORT bufWidth = csbi.dwSize.X;

        char* padded = (char*)malloc((size_t)bufWidth + 1);
        for (DWORD i = 0; i < lb.count; i++) {
            size_t len = strlen(lb.lines[i]);
            size_t copyLen = len < (size_t)bufWidth ? len : (size_t)bufWidth;
            memcpy(padded, lb.lines[i], copyLen);
            memset(padded + copyLen, ' ', (size_t)bufWidth - copyLen);
            padded[bufWidth] = '\0';

            DWORD written = 0;
            COORD pos = { 0, (SHORT)i };
            WriteConsoleOutputCharacterA(hConsole, padded, (DWORD)bufWidth, pos, &written);
        }

        if (lb.count > maxLinesEverDrawn) maxLinesEverDrawn = lb.count;
        memset(padded, ' ', (size_t)bufWidth);
        padded[bufWidth] = '\0';
        for (DWORD i = lb.count; i < maxLinesEverDrawn; i++) {
            DWORD written = 0;
            COORD pos = { 0, (SHORT)i };
            WriteConsoleOutputCharacterA(hConsole, padded, (DWORD)bufWidth, pos, &written);
        }

        free(padded);
        LineBufferFree(&lb);

        Sleep(REFRESH_INTERVAL_MS);
    }

    return 0;
}
