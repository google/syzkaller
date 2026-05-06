# Bugs scoring

Until triaged we don't really know the bug impact. But we can learn a lot from the bug title.

Syzbot scoring is based on our understanding of what bug class looks historically more impactful. It allows to
prioritize the triaging queue.

## Heuristics

### KASAN > KMSAN > KCSAN
KASAN detected bugs are typically more dangerous than KMSAN detected bugs. And KMSAN detected bugs are typically more
dangerous than KCSAN detected bugs.

### Invalid-free (double-free) >= use-after-free write > use-after-free read.

### KASAN write > KASAN read
KASAN write indicates an out-of-bounds or use-after-free write operation. Any uncontrolled write to kernel memory is
extremely dangerous because it can corrupt data or code pointers, making it a high-value target for exploitation
and leading to system compromise. KASAN read indicates an out-of-bounds or use-after-free read. This is generally
less critical. It can crash the system (DoS) or leak sensitive data, but it doesn't provide a direct path for an
attacker to execute their own code.

### Memory Safety bugs > DoS bugs.
This heuristic establishes a broad priority between two major classes of bugs based on their ultimate impact.

Memory Safety bugs: This category includes all the issues mentioned above—use-after-free, double-free, out-of-bounds
reads/writes, etc. These are considered more severe because they represent a potential system compromise. A successful
exploit can allow an attacker to escalate privileges and gain complete control over the kernel and the entire system.

DoS bugs (Denial of Service): This category includes bugs like kernel hangs, crashes, or resource exhaustion
(e.g., memory leaks). While they are serious because they disrupt system availability, they typically do not allow an
attacker to execute code or steal data. The impact is usually temporary and can be resolved by rebooting the system.
They disrupt the service but don't compromise its integrity.

### Information Leaks > Denial of Service (DoS)
Kmsan infoleak and other bugs that leak kernel memory are generally more severe than a typical DoS. These leaks can be
used to bypass security mitigations like Kernel Address Space Layout Randomization (KASLR), which makes exploiting
other vulnerabilities easier.

### Concurrency Issues > Simple DoS
Bugs like DataRace and LockdepBug can be more critical than a standard DoS. Data races can lead to unpredictable
behavior, including memory corruption, which might be exploitable.

LockdepBug indicates potential deadlocks, which can cause a more severe system Hang than a resource-exhaustion DoS.

### KFENCE reports are high priority
KFENCE is a lighter-weight memory safety detector compared to KASAN. While it may have a lower performance overhead,
the bugs it finds (use-after-free, out-of-bounds) are of the same high-impact nature as those found by KASAN.
Therefore, KFENCE detected bugs should be treated with a similar level of urgency as KASAN reports.

### UBSAN reports require careful evaluation
The Undefined Behavior Sanitizer (UBSAN) can detect a wide range of issues. Their severity can vary greatly:

1. A shift-out-of-bounds or array-index-out-of-bounds issue can be very severe if it leads to memory corruption.
2. An integer-overflow can also be critical if it results in bypassing security checks and leads to a buffer overflow.
3. Other UBSAN issues might be less critical but still indicate latent bugs that could become problematic.

### LockdepSleeping in Atomic Context is a critical flaw
AtomicSleep is a serious bug that can lead to system-wide hangs and instability. This is because holding a spinlock
or being in another atomic context while sleeping can cause deadlocks.

These are generally more severe than a typical DoS.

### Memory Leaks are a form of DoS
MemoryLeak bugs are a type of denial of service where the kernel gradually runs out of memory. While generally less
severe than memory corruption, a fast memory leak that can be triggered by an unprivileged user can be a high-impact
DoS vector.

### NULL pointer dereference in reads/writes
They may be exploitable (see [proof](https://googleprojectzero.blogspot.com/2023/01/exploiting-null-dereferences-in-linux.html ))
but the exploitation probability is not clear. Because of this uncertainty they are put to the bottom of the high
priority bugs.
