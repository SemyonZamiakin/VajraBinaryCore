# Security policy

## Supported versions

Only the latest release of Vajra Binary Core receives security fixes.

## Reporting a vulnerability

Please do not publish exploit details in a public issue.

1. Use GitHub private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**.
2. If that option is not available, open an issue titled "Security contact request" without technical details, and a private channel will be arranged.

Expect an acknowledgement within a few days. This is a small project maintained by one person; there is no bug bounty.

## Threat model

Vajra rewrites machine code and live data inside the process that links it. That is a privileged operation by nature: whoever can apply a patch can run arbitrary code in the process. Vajra therefore never attaches to a process on its own; the program must link the library and, if it wants remote control, start the agent.

| Concern | Status |
|---|---|
| Another local user applying patches through the agent | Protected. Linux: socket created with mode 0600 and every connection's peer uid (`SO_PEERCRED`) must equal the process's effective uid. Windows: named pipe with a protected DACL for the current user's SID only |
| Remote clients | Protected. Unix sockets are local; the Windows pipe uses `PIPE_REJECT_REMOTE_CLIENTS` |
| Name squatting (someone creates the socket / pipe first) | Linux: an existing path is replaced only if it is a socket owned by the same user; put the socket in a private directory. Windows: `FILE_FLAG_FIRST_PIPE_INSTANCE` makes the agent fail if the name already exists |
| Swapping a module file between the check and the load | Protected. Linux loads through the checked descriptor (`/proc/self/fd/N`, opened with `O_NOFOLLOW`); Windows holds the file open without write sharing while `LoadLibrary` maps it and refuses reparse points |
| Modules owned by other users or writable by others | Refused (owner must be the current user or root; Windows also accepts Administrators, SYSTEM and TrustedInstaller). Linux also refuses group/world-writable files; **Windows does not inspect the file's DACL beyond the owner** |
| A process running as the **same user** applying patches | **Not prevented, by design.** Same-user processes can already debug and modify each other. Do not start the agent in a process that runs with more privileges than the users who can reach its socket |
| A malicious patch module | Out of scope. A module is native code; applying it is equivalent to running it |
| A buggy patch (wrong layout description, detour with the wrong signature) | Partly. Layout descriptions are validated and checked against the heap's current version, stale allocations are refused, strict conversions refuse lossy values. Function signatures cannot be checked |
| Memory left writable and executable | Not by default. Code pages are written through `/proc/self/mem` (Linux) or made writable without execute permission while every other thread is stopped. `WriteMethod::MprotectRWX` (opt-in) briefly maps pages RWX; on Windows `WriteProcessMemory`, used for pages of ntdll/kernelbase/kernel32, may do so internally |
| Denial of service through the agent | Limited: one command per connection, 4 KiB line limit, 5 s read timeout, one connection at a time. A same-user client can still keep the agent busy |

## In scope

- Memory-safety bugs in the decoder, relocator, migration engine, ELF/PE parsers and the agent protocol.
- Ways to make the agent load a module or execute a command for a different user.
- Cases where a failed transaction leaves code or data partially modified.

## Out of scope

- What a correctly loaded patch module does.
- Attacks that require the same user account or administrator rights.
- Using Vajra as a hooking library inside malware; the library is intentionally opt-in and in-process only.
