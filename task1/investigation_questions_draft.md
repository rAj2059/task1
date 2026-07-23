# Task 1 — Draft Investigation Question Answers

> DRAFT MATERIAL ONLY. Rewrite substantially in your own words before
> submitting. These are grounded in the actual backend.c/frontend.c
> implementation and test runs, so cross-reference the code and your
> own logs as you rewrite, and add your own critical voice/evaluation
> per the marking criteria (First-class answers show "original ideas"
> and "critical analysis," not just correct description).

---

**1. Why is it considered insecure for a single process to receive user input and access sensitive authentication data on a Linux system?**

A single process that both parses user-supplied input and holds access to sensitive credential data violates the principle of least privilege at the most basic level: any vulnerability in the input-handling code (buffer overflow, format string bug, integer overflow, etc.) runs with the full privilege of that process, meaning an attacker who compromises the input path immediately has access to whatever the process was authorised to do — in this case, reading the password store. Because input parsing is inherently the most attack-exposed part of any authentication service (it processes data from an untrusted source by definition), it should have the *least* privilege, not the most. In our implementation, this is why `frontend.c` never touches `/etc/mypasswd` at all — even a full compromise of the frontend (e.g. a crafted username overflowing a fixed-size buffer) gives an attacker nothing more than the invoking user already had, because the frontend never held elevated rights to begin with. Combining input handling and privileged data access in one process removes this isolation boundary entirely and turns every input-parsing bug into a direct credential-disclosure or privilege-escalation bug.

---

**2. How can the principle of least privilege be enforced at the operating system level using multiple processes rather than threads?**

Threads within one process share the same address space, the same UID/GID, and the same open file descriptors — there is no OS-enforced boundary between them; isolation between threads exists only by programmer convention. Processes, by contrast, each get their own address space, and (critically for this task) can each run under a *different* UID with the kernel enforcing which files, sockets, and resources that UID is permitted to access. In `backend.c`, the enforcement mechanism is `setresuid()`: after the privileged file read, the process's real/effective/saved UID are all set to an unprivileged account, and from that point on the *kernel itself* refuses any operation requiring root — it is not a self-imposed limitation the process could accidentally violate through a bug, since the OS's permission checks apply regardless of what the code does afterward. Splitting frontend and backend into separate processes means the frontend never has the *capability* to be privileged, even in principle, which is a stronger guarantee than "the frontend code doesn't currently do anything privileged."

---

**3. What risks remain if privilege dropping is incorrectly implemented?**

The most direct risk is an incomplete drop: calling `seteuid()` alone (rather than `setresuid()`) changes only the *effective* UID and leaves the *saved* UID at 0, meaning a compromised process can call `seteuid(0)` again and silently regain root — the drop is reversible and therefore not a real security boundary. Another risk is ordering: if privileged operations happen *after* the drop instead of before, the drop achieves nothing (the process still needs root when it matters). A third risk is partial drop across threads: `setresuid()` on Linux affects only the calling thread unless `setuid()`-family syscalls are used correctly with all threads considered (a known historical source of bugs in multi-threaded privilege-dropping code — for a single-threaded backend like ours this isn't an issue, but it's worth noting as a design constraint if the backend were ever extended to be multi-threaded). Finally, failing to *check* that the drop succeeded (as `verify_privilege_dropped()` does in our implementation) means a silently failed `setresuid()` call — for example due to a resource limit or a coding error in argument order — could leave the process running as root while the rest of the code proceeds as if it were safe, which is arguably worse than never attempting the drop, because it creates false confidence.

---

**4. How can two independent processes securely exchange authentication requests and results without exposing sensitive data to unauthorized processes?**

The mechanism used here is a UNIX domain socket at a filesystem path (`/tmp/authsock` in our implementation), which gives several security properties simultaneously: the socket exists as a filesystem object, so standard Unix file permissions can restrict which users/groups may even open a connection to it; the kernel provides `SO_PEERCRED`, letting the receiving process ask the kernel — not the sender — for the real UID/GID/PID of whoever connected, which cannot be spoofed by the connecting process; and because it's a local, kernel-mediated channel rather than a network socket, the data never leaves the machine or touches any network-visible interface, removing an entire class of interception risk. In `backend.c`, `check_peer_is_legitimate()` uses `SO_PEERCRED` specifically so the backend is not relying on anything the frontend *claims* about itself in the message payload — it is independently verified by the OS.

---

**5. Why are UNIX domain sockets preferable to network sockets for local privileged communication?**

Network sockets (`AF_INET`/`AF_INET6`) route through the kernel's network stack even for `localhost` traffic, which means the communication is, in principle, subject to anything else on the system capable of observing loopback traffic, and network sockets identify peers only by IP:port — there is no kernel-verified notion of "which OS user process is on the other end" the way `SO_PEERCRED` provides for UNIX domain sockets. UNIX domain sockets also benefit from filesystem permission enforcement (who can even `connect()` to the socket path) and don't require binding a port that could be discovered or connected to by an unrelated process on the same machine attempting to impersonate the frontend. For a purpose-built local IPC channel between two processes that are meant to talk *only* to each other, UNIX domain sockets give strictly more OS-level identity and access guarantees with less attack surface than a network socket would.

---

**6. What operating system mechanisms allow controlled sharing of data between processes without violating isolation?**

Beyond the UNIX domain socket used here, Linux provides several controlled-sharing mechanisms, each trading off convenience against how much isolation is preserved: pipes/FIFOs (simple byte streams, similar trust model to what we use); System V or POSIX shared memory segments (`shmget`/`mmap` with `MAP_SHARED`), which are fast but require the processes to explicitly coordinate access (typically with semaphores) since the kernel does not serialize access for you; and `SCM_RIGHTS` ancillary messages over UNIX sockets, which let one process pass an open file descriptor to another under kernel mediation. What all of these have in common is that sharing is *explicit and opt-in* — a process must deliberately create or connect to the shared resource; nothing is accidentally shared as a side effect of process creation the way memory is shared between threads. Our design deliberately avoids raw shared memory in favour of a socket precisely because socket message-passing has a much smaller and easier-to-reason-about attack surface than a shared memory region that both privileged and unprivileged code might read/write.

---

**7. How can a process permanently relinquish root privileges after startup, and why must this be irreversible?**

The kernel maintains three UID values per process: real, effective, and saved. `setuid()`/`seteuid()` typically only change the effective UID and leave a saved UID of 0 in place, which means a process that has only "dropped" via `seteuid()` can call `seteuid(0)` again later and become root once more — this is not a true relinquishment, merely a temporary effective-privilege change (useful for things like alternating between privileged and unprivileged operations, but not for a one-way security boundary). `setresuid(uid, uid, uid)`, as used in `backend.c`, sets *all three* — real, effective, and saved — to the unprivileged UID in a single atomic call. With no value of 0 stored anywhere in the process's credential state, there is nothing left to `setuid()` back to; the drop is irreversible by construction, not by convention. This matters because the whole point of privilege dropping is to guarantee that even if the *remaining* code (everything that runs after the drop, including all of the attacker-influenced password-comparison logic) is compromised, the attacker cannot regain root through that process, no matter what code executes afterward.

---

**8. What observation system indicators can be used to verify that privilege dropping has succeeded?**

Our implementation uses two independent methods, deliberately, so one can cross-check the other: `getresuid()`, a direct syscall returning the real/effective/saved UID values as the kernel currently has them recorded for the calling process; and reading the `Uid:` line from `/proc/self/status`, which exposes the same information via the `/proc` filesystem and is useful because it's also externally observable — a separate monitoring process (or an administrator running `cat /proc/<pid>/status`) can confirm the drop from outside the process being checked, without trusting that process's own self-report. In our test run the backend logged `getresuid() -> real=996 effective=996 saved=996` and `/proc/self/status -> Uid: 996 996 996 996`, and the code explicitly aborts (`exit(1)`) if `euid == 0` is still observed after the `setresuid()` call, rather than silently continuing — treating a failed drop as a fatal error rather than a warning.

---

**9. How would an attacker benefit if a process unintentionally retained elevated privileges?**

Any vulnerability discovered afterward in the "unprivileged" portion of the code — for example a bug in the password-comparison logic, an unchecked buffer, or an unexpected input that triggers undefined behaviour — would then execute with root privilege rather than the intended restricted account. Concretely, in our design, the code that runs after the (intended) privilege drop reads and compares the submitted password, an operation directly driven by attacker-controlled input; if the drop had silently failed, an attacker able to trigger a bug in that comparison logic (e.g. via a crafted socket payload) would be exploiting it *as root*, potentially gaining arbitrary file access, the ability to modify the password store itself, or a foothold to escalate further — rather than being contained to a throwaway service account with no meaningful access. This is precisely why the design treats a failed or unverified privilege drop as fatal rather than proceeding regardless.

---

**10. Why is clearing sensitive data from memory a security requirement even after authentication is complete?**

Plaintext passwords left in memory after use remain readable by anything with a legitimate or illegitimate way of inspecting that process's memory: a core dump generated by a crash (which may be written to disk and persist long after the process exits), a debugger attached to a running or paused process, or — in a multi-user or virtualised environment — techniques that can read stale memory pages after they've been freed and before they're overwritten with unrelated data. Without explicit clearing, the password isn't protected by the program's control flow "moving on" from it; it simply sits in memory until something else happens to overwrite that location, which could be seconds or much longer. Wiping it as soon as it's no longer needed shrinks the window during which any of these exposure paths could leak it.

---

**11. Why can standard memory clearing functions be unreliable according to the C language memory model?**

The C standard only guarantees that a program's *observable behaviour* (its outputs, side effects on volatile objects, etc.) matches what the code specifies — it says nothing about intermediate memory states that no subsequent code reads. A `memset()` call that zeroes a local buffer immediately before that buffer goes out of scope, with nothing afterward reading it, has no effect on the program's observable behaviour, so an optimizing compiler is standard-conformant if it removes the call entirely as a "dead store." This isn't a hypothetical: compiling the demonstration file `wipe_demo.c` at `-O2` and disassembling it with `objdump -d` shows exactly this — `wipe_with_memset()`'s body, including the preceding `strcpy()` that wrote the fake password in the first place, is eliminated entirely by GCC, leaving essentially nothing in the compiled function. The security-relevant consequence is that a developer can write code that *looks* like it wipes sensitive data and yet, after compilation with optimisation enabled, does nothing of the sort — with no warning and no change in the program's ordinary output.

---

**12. How does the use of explicit memory primitives mitigate this risk?**

`explicit_bzero()` (used in both `backend.c` and `frontend.c` after the password buffer is no longer needed) is specified — as a matter of its API contract, not merely its typical implementation — to always perform the memory write, regardless of what the compiler can prove about subsequent reads. Implementations achieve this in different ways (e.g. routing the call through a function pointer the compiler cannot see through, or using a memory barrier), but the practical effect is the same: unlike `memset()`, the call cannot be treated as a provably-dead store and eliminated. The same disassembly comparison used for question 11 demonstrates this directly: `wipe_with_explicit_bzero()`'s compiled output contains a genuine `call` instruction to the wiping routine, present in the `-O2` binary exactly as written, whereas the `memset()` equivalent has none. This makes `explicit_bzero()` (or equivalents like `memset_s()` on platforms that provide it) the correct primitive for clearing sensitive data specifically *because* it closes the gap between "the source code says the data is wiped" and "the compiled binary actually wipes it."

