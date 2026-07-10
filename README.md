# ZombieScanner

A Windows zombie process detector and live monitor — finds EPROCESS objects kept alive by dangling handles after a process has exited, using system-wide handle enumeration. No kernel driver required.

## What's a zombie process?

When a Windows process exits, the kernel tears down its address space, closes its own handle table, and unlinks it from `PsActiveProcessHead` — the list that standard enumeration APIs (Task Manager, `CreateToolhelp32Snapshot`, `NtQuerySystemInformation(SystemProcessInformation)`) walk. But the EPROCESS object itself isn't freed until the object manager's reference count on it reaches zero.

If some other process still holds an open `HANDLE` to that process (e.g. it called `CreateProcess`/`OpenProcess` and never closed the resulting handle), the EPROCESS object lingers in memory as a **zombie**: it has a PID, but no threads, no address space, and no handle table of its own — and it no longer shows up in any normal process listing.

## How it works

1. **Baseline** — snapshot the set of currently active PIDs via `CreateToolhelp32Snapshot`.
2. **Dump every handle on the system** via `NtQuerySystemInformation(SystemExtendedHandleInformation)`.
3. For every handle whose object type is `Process`, resolve which PID it actually points to (`DuplicateHandle` + `GetProcessId`).
4. If that PID isn't in the baseline, it's a zombie. Multiple processes can independently hold handles to the same zombie — each `(zombie, maker)` pair is tracked separately, along with how many handles that maker holds.
5. Names are resolved via `NtQuerySystemInformation(SystemProcessIdInformation)` for zombies (a PID-based lookup that still works even though the zombie's Section object is already gone) and via `QueryFullProcessImageName` for makers (still-alive processes, so the normal handle-based path works fine).

The `Process` object type index used to filter the handle dump isn't hardcoded — it's resolved empirically once at startup by matching a known-good handle against the dump, since the index can vary across Windows builds.

## Build

Requires the MSVC toolchain (x64 Native Tools Command Prompt):

```
cl /W4 /EHsc zombiescan.c /link ntdll.lib
```

## Run

```
zombiescan.exe
```

Run as **Administrator** — `SeDebugPrivilege` is required to duplicate handles owned by processes outside your own session/user. The tool re-scans and redraws the table every 2 seconds; stop it with **Ctrl+C**.

## Disclaimer

This is a diagnostic tool built for exploring Windows process internals — not a general-purpose leak detector. Interpreting a "zombie" as a bug in the maker process requires judgment: sometimes it's an intentional design (e.g. a supervisor process deliberately keeping a handle to check exit codes later).
