# ADR 0003: Lossy entity keys instead of raw-string identity

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

The same process shows up in each artefact with a different spelling:

| Source | Spelling of the same process |
| --- | --- |
| Sysmon EID 1 | `ProcessId=4321`, `C:\Windows\System32\reg.exe` |
| Security 4688 | `NewProcessId=0x10e1`, `C:\Windows\System32\REG.EXE` |
| Volatility `pslist` | `PID=4321`, `reg.exe` (EPROCESS name, max 14 chars) |
| plaso prefetch | `REG.EXE` (no PID) |

Hosts appear both as `WORKSTATION5` and `WORKSTATION5.theshire.local`.

## Decision

`entities.py` defines deliberately lossy keys:

- `norm_pid`: hex or decimal becomes a decimal string.
- `image_key`: lower-cased basename truncated to 14 characters (the EPROCESS
  limit), so memory and log spellings agree.
- `norm_host`: short lower-case host name.
- `norm_user`: `DOMAIN\user` and `user@domain` both become `user`.
- `process_key`: `host|pid|image_key`, the key used by rules and fusion.

Raw values are never overwritten. Events keep their original strings, and
only the *comparison* uses keys.

## Consequences

- Two different executables with the same 14-character prefix, PID and host
  at the same moment would collide. The termination guard and nearest-cause
  selection make this very unlikely, and the benchmark would reveal it.
- Keys are one module, so a new artefact source only has to map into them.
