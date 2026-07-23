# Task 1 — Privilege-Separated Password Validator

## Files
- `backend.c` — setuid-root service: reads the password store while
  privileged, then permanently drops privilege before touching
  attacker-controlled data.
- `frontend.c` — unprivileged client: collects credentials, talks to
  backend over a UNIX domain socket, never elevated.
- `wipe_demo.c` — standalone evidence for the memory-wipe investigation
  questions (see below).
- `backend*.log` — captured output from three test runs (success,
  wrong password, rejected root peer).

## One-time setup (run as root)

```bash
# 1. Dedicated unprivileged account the backend drops into
sudo useradd -r -s /usr/sbin/nologin authnobody

# 2. Mock password store, root-only readable
sudo tee /etc/mypasswd > /dev/null << 'EOF'
alice:hunter2
bob:correcthorse
EOF
sudo chown root:root /etc/mypasswd
sudo chmod 600 /etc/mypasswd
```

## Build

```bash
gcc -Wall -Wextra -O2 -o backend backend.c
gcc -Wall -Wextra -O2 -o frontend frontend.c
```

## Install backend as setuid-root

```bash
sudo cp backend /usr/local/bin/backend
sudo chown root:root /usr/local/bin/backend
sudo chmod 4755 /usr/local/bin/backend
```

## Run (two terminals, or one terminal + `&`)

```bash
# Terminal 1 — launch ONCE as a NORMAL user; euid will be root due to setuid bit.
# The listener stays alive and keeps accepting connections until you Ctrl+C it —
# you do NOT need to relaunch it between test runs.
/usr/local/bin/backend

# Terminal 2 — also a normal user, run as many times as you like against the
# same backend instance
./frontend
Username: alice
Password: hunter2
```

Each connection is handed off to a freshly forked worker process that inherits
root from the listener, does the one privileged file read, permanently drops
via `setresuid()`, does the comparison, and exits — the listener itself never
drops privilege and never touches request data directly. This is the same
privileged-monitor / disposable-unprivileged-worker pattern used by real
daemons such as OpenSSH, and lets one backend instance safely serve many
authentication attempts in a row. See `persistent_backend_multi_request.log`
for a captured run of three consecutive requests (a failed lookup, then two
successful logins) served by a single long-lived backend process, each by a
different worker PID.

Watch the log: you'll see `euid=0` at listener startup, then for each request
a new `[backend worker <pid>]` line showing that specific worker's
`setresuid()` drop and result, confirmed via two independent methods
(`getresuid()` and `/proc/self/status`) before any password comparison
happens.

## Reproducing the memory-wipe evidence

```bash
gcc -O2 -c wipe_demo.c -o wipe_demo.o
objdump -d wipe_demo.o
```

Compare the two disassembled functions: `wipe_with_memset` should
compile to almost nothing (the compiler eliminates the whole function
as a dead store), while `wipe_with_explicit_bzero` contains a genuine
`call` instruction. This is your evidence for investigation questions
11–12.

## Deliverable → code mapping

| Deliverable | Where |
|---|---|
| Two independent processes (not threads) | `frontend.c` / `backend.c`, separate binaries |
| Process isolation via fork/execve-style separation | Achieved structurally: two executables, invoked independently by the OS, not spawned via `fork()` from a shared parent — discuss the tradeoff of this vs a fork()+execve() launcher in your report |
| Secure IPC | `AF_UNIX` `SOCK_STREAM` socket at `/tmp/authsock` |
| Actual `setresuid()` call | `backend.c`, in `main()`, after reading the password hash |
| Runtime check via `geteuid()`/`/proc` | `verify_privilege_dropped()` |
| Attack resistance | `check_peer_is_legitimate()` using `SO_PEERCRED` |
| Secure memory handling | `secure_wipe()` using `explicit_bzero()`; see `wipe_demo.c` for proof |

## Note on the assignment's "process isolation" wording

The brief lists `fork()`/`execve()` as an *example* isolation
mechanism, but the actual requirement is **two distinct executables**
running as separate OS processes — which this satisfies. If your
module leader specifically wants to see a `fork()`+`execve()` launcher
(one program that spawns the other), that's a straightforward addition:
a small `launcher.c` that `fork()`s and `execve()`s `frontend` and
`backend`. Worth confirming with your tutor which they expect, and
documenting your choice either way in the report — that's exactly the
kind of design justification the marking criteria reward.
