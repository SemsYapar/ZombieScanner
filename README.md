# ZombieScanner
A Windows zombie process detector and live monitor. It finds EPROCESS objects kept alive by dangling handles after a process has exited, using system-wide handle enumeration. No kernel driver required.
## What's a zombie process?
When a Windows process exits, the kernel tears down its address space, closes its own handle table, and unlinks it from `PsActiveProcessHead`, the list that standard enumeration APIs (Task Manager, `CreateToolhelp32Snapshot`, `NtQuerySystemInformation(SystemProcessInformation)`) walk. But the EPROCESS object itself isn't freed until the object manager's reference count on it reaches zero.
If some other process still holds an open `HANDLE` to that process (for example it called `CreateProcess`/`OpenProcess` and never closed the resulting handle), the EPROCESS object lingers in memory as a zombie. It has a PID, but no active threads, no address space, and no handle table of its own, and it no longer shows up in any normal process listing.
## How it works
1. Baseline: snapshot the set of currently active PIDs via `CreateToolhelp32Snapshot`.
2. Dump every handle on the system via `NtQuerySystemInformation(SystemExtendedHandleInformation)`.
3. For every handle whose object type is `Process`, resolve which PID it actually points to (`DuplicateHandle` + `GetProcessId`).
4. If that PID isn't in the baseline, it's a zombie. Multiple processes can independently hold handles to the same zombie, so each `(zombie, maker)` pair is tracked separately, along with how many handles that maker holds.
5. Names are resolved via `NtQuerySystemInformation(SystemProcessIdInformation)` for zombies (a PID-based lookup that still works even though the zombie's Section object is already gone) and via `QueryFullProcessImageName` for makers, which are still-alive processes, so the normal handle-based path works fine there.
## Resolving the Process object type index
Filtering the handle dump down to `Process` handles requires knowing the numeric `ObjectTypeIndex` the kernel assigns to that type, but this index isn't a fixed constant. It's assigned at boot time based on the order object types get registered, so it can differ across Windows builds.

In practice, testing this across multiple boots on the same machine kept producing the same index for `Process` every time. Whether it genuinely varies (across different Windows versions, different driver load orders, etc.) or is effectively constant in practice isn't fully confirmed here, so `ResolveProcessTypeIndexOnce()` is kept as a safety measure rather than a confirmed requirement.

The naive fix would be parsing `NtQueryObject(NULL, ObjectTypesInformation, ...)`, which returns every registered type's name alongside its index. This was tried and dropped: the struct layout after each type's name (padding, reserved fields) isn't consistent across Windows versions, which makes computing the stride between entries in that array fragile and error-prone.
Instead, the index is found empirically:
1. Open a handle to the tool's own process (`OpenProcess` on `GetCurrentProcessId()`). This handle's type is known to be `Process` with certainty.
2. Take the system-wide handle dump.
3. Search the dump for the entry whose `UniqueProcessId` and `HandleValue` match that self-handle. Its `ObjectTypeIndex` field is, by construction, the real index for `Process` on this specific build.
## Build
Requires the MSVC toolchain (x64 Native Tools Command Prompt):
```
cl zombiescan.c /link ntdll.lib
```
## Run
```
zombiescan.exe
```
Run as Administrator. `SeDebugPrivilege` is required to duplicate handles owned by processes outside your own session/user. The tool re-scans and redraws the table every 2 seconds. Stop it with Ctrl+C.
## Disclaimer
This is a diagnostic tool built for exploring Windows process internals, not a general-purpose leak detector. Interpreting a zombie as a bug in the maker process requires judgment. Sometimes it's intentional design, for example a supervisor process deliberately keeping a handle to check exit codes later.

## Run Result Example
<img width="1098" height="470" alt="image" src="https://github.com/user-attachments/assets/492fe5d2-a2d1-48fa-bd7e-72b5298af60b" />

## Update
Cross-checking results against Pavel Yosifovich's ObjExp turned up a zombie ZombieScanner was missing. The cause was `DuplicateHandle` being called with `DUPLICATE_SAME_ACCESS`: some source handles carry a very narrow access grant (confirmed via Process Explorer as `0x40`, `PROCESS_DUP_HANDLE` only), and `SAME_ACCESS` carried that same narrow grant over to the duplicate. `GetProcessId()` needs `PROCESS_QUERY_LIMITED_INFORMATION`, which wasn't in that grant, so it failed silently and the zombie was dropped without any error being visible. The fix was requesting `PROCESS_QUERY_LIMITED_INFORMATION` explicitly instead of `DUPLICATE_SAME_ACCESS`. Since `SeDebugPrivilege` is enabled, this request is checked against the process object directly rather than being limited by whatever access the original handle happened to have.

## Extra
[My article](https://semsyapar.github.io/2026/07/10/zombie-processes.html) about this topic, turkish
