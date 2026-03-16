# rev_this_#.bin — Reverse Engineering Writeup

> **Ramadhan CTF** organized at **ISET'COM**  
> Category: Reverse Engineering | Binary: ELF 64-bit, .NET 6 Self-Contained

---

## Table of Contents

- [Overview](#overview)
- [Step 1 — Identify the Binary](#step-1--identify-the-binary)
- [Step 2 — Find the .NET Bundle](#step-2--find-the-net-bundle)
- [Step 3 — Extract revproj.dll](#step-3--extract-revprojdll)
- [Step 4 — Analyze the Managed Assembly](#step-4--analyze-the-managed-assembly)
- [Step 5 — Inspect the Static Constructor IL](#step-5--inspect-the-static-constructor-il)
- [Step 6 — Decrypt the Flag](#step-6--decrypt-the-flag)
- [Step 7 — Verify the Result](#step-7--verify-the-result)
- [Final Flag](#final-flag)

---

## Overview

This repository contains the solution walkthrough for **rev_this_#.bin**, a reverse engineering challenge from **Ramadhan CTF organized at ISET'COM**.

Reverse engineering is the process of analyzing a program **without having its source code**. You only have the compiled binary — a file the computer can run — and your job is to figure out what it does, how it works, and in CTF challenges, how to extract a hidden secret called a **flag**.

In this challenge, the binary looks like a normal Linux program from the outside, but it hides a `.NET` assembly (essentially a second program) inside itself. That inner program contains the encrypted flag. Our goal is to find it, understand the encryption, and reverse it to recover the original flag text.

**Key concepts covered:**
- ELF binary analysis
- .NET single-file bundle extraction
- .NET metadata stream parsing (#US, FieldRVA)
- XOR decryption
- SHA-256 hash verification

---

## Step 1 — Identify the Binary

Before doing anything else, we need to understand what kind of file we are dealing with. A compiled program is just a long sequence of bytes — it has no obvious label saying what it is. The `file` command reads the first few bytes of the file (called **magic bytes**) and tells us the file format.

```bash
file rev_this_#.bin
```

**Output:**
```
rev_this_#.bin: ELF 64-bit LSB executable, x86-64, stripped
```

Let's break down what this means:

- **ELF** — the standard format for executable programs on Linux, the same way `.exe` is the format on Windows.
- **64-bit** — the program is compiled for modern 64-bit processors.
- **x86-64** — the specific CPU instruction set used (the most common on desktop and server computers).
- **stripped** — all debug information has been deliberately removed. Normally, a compiled program keeps some human-readable labels (like function names) to help developers debug it. "Stripped" means those labels are gone, making it harder for us to understand what the program does.

When you actually run the binary, it asks for a flag:

```
Enter Flag:
Debugger Detected!
```

It immediately prints "Debugger Detected!" — this is an **anti-debugging trap**. The program checks whether a reverse engineering tool is watching it, and if so, it behaves differently to frustrate the analyst. This is a common protection technique in CTF challenges and real-world malware alike.

> **Note:** The strings "Enter Flag:" and "Debugger Detected!" do **not** appear if you search the binary with a tool like `strings`. That is because the developer encoded them in hexadecimal and only converts them back to readable text at the moment the program needs to display them. This is called **runtime string obfuscation** — a way to hide readable text from basic analysis tools.

---

## Step 2 — Find the .NET Bundle

Now that we know it is a Linux ELF binary, let's dig deeper. When you look at the raw bytes of the file more carefully, something unusual stands out: this binary is actually a **.NET 6 self-contained application**.

To understand what that means, imagine you wrote a program in C# (a Microsoft programming language). Normally, to run a C# program on Linux you would need to have the .NET runtime installed separately. But .NET 6 introduced a feature called **single-file publishing**: it takes your C# program and the entire .NET runtime and packs them all into one single file. The result looks like a normal Linux ELF binary from the outside, but it secretly carries a `.NET DLL` — the actual C# program — hidden inside it.

Our job in this step is to find where inside the ELF that hidden `.NET DLL` begins. To do this, we search the binary for a known **magic byte sequence** — a fixed pattern of 8 bytes that Microsoft always places at the start of the embedded bundle:

```
8B 12 02 B9 6A 61 20 38
```

Think of it like searching a very long book for a specific rare phrase in order to find a particular chapter. Once we find this sequence in the file, we know we are at the bundle header.

An **offset** is simply the distance from the very beginning of the file, measured in bytes. If a file is a long hallway, the offset tells you how many steps from the entrance a particular door is located.

| Item | Value |
|------|-------|
| Magic bytes offset | `0xa23018` |
| Bundle header pointer (8 bytes before magic) | `0x3d31529` |

The 8 bytes sitting just before the magic sequence contain a pointer — a number that tells us the exact offset of the **bundle header**, which is the index listing all files embedded inside the binary. We found it at offset `0x3d31529`.

---

## Step 3 — Extract revproj.dll

Now that we have the bundle header location, we can read the **bundle table** — a directory of every file packed inside the binary, along with the location and size of each one.

Each entry in this table starts with a small header that identifies the file. We search for the entry corresponding to the main C# program file:

```
\x01\x0brevproj.dll
```

This looks cryptic but it is straightforward:

| Byte | Meaning |
|------|---------|
| `0x01` | This file is a managed assembly (a .NET DLL containing compiled C# code) |
| `0x0b` | The number `11` in decimal — the length of the filename `revproj.dll` |

Right before this entry, there are 24 bytes of metadata that tell us exactly where the DLL is stored inside the binary and how large it is:

| Field | Value |
|-------|-------|
| Offset | `0xa49730` |
| Size | `10240` bytes |
| Compressed size | `0` (not compressed) |

The compressed size being `0` means the file was stored as-is, without any compression applied. That makes our job easy: we just read exactly **10,240 bytes** starting from position `0xa49730` in the binary, and we get a complete, valid `.NET DLL` file.

This extracted file — `revproj.dll` — starts with the bytes `MZ`, which is the magic signature of a Windows PE (Portable Executable) file. Even though it was buried inside a Linux binary, the DLL itself is in the standard Windows format that all .NET analysis tools can read. We can now open it with a .NET decompiler and examine the actual C# logic.

---

## Step 4 — Analyze the Managed Assembly

With `revproj.dll` in hand, we analyze its internal structure. Every .NET DLL is organized into sections called **metadata streams**. These streams are like chapters in a book, each responsible for storing a different type of information about the program:

```
#~        ← the main tables stream: contains method definitions, field locations, type info
#Strings  ← stores identifier names like class names and method names
#US       ← User Strings: stores the actual string values used in the code
#Blob     ← stores raw binary data like method signatures
```

### String Obfuscation

The first interesting discovery is in the **#US (User Strings)** stream. Normally this is where you would find readable strings like `"Enter Flag:"` stored in plain text. But here, every string is stored in hexadecimal encoding instead. The program converts them to readable text only when it needs to display them, which is why they were invisible to the `strings` command earlier.

Decoding the hex is straightforward — each pair of hex digits represents one character:

```
456e74657220466c61673a20        →   "Enter Flag:"
416363657373204772616e74656421  →   "Access Granted!"
```

### Static Byte Arrays (FieldRVA Table)

The more important discovery is in the **#~ stream**, specifically in a sub-table called **FieldRVA**. This table tells us about static byte arrays — blocks of raw binary data that are baked directly into the program file at compile time and loaded into memory when the program starts.

We found four such arrays. Their purpose becomes clear once we see how the program uses them:

| Field | Size | Purpose |
|-------|------|---------|
| `Field[8]` | 48 bytes | `XOR_KEY` — the secret key used to encrypt and decrypt the flag |
| `Field[10]` | 24 bytes | `FLAG_A` — the encrypted first half of the flag |
| `Field[9]` | 24 bytes | `FLAG_B` — the encrypted second half of the flag |
| `Field[11]` | 32 bytes | `TARGET_HASH` — a SHA-256 fingerprint of the correct flag, used to verify the answer |

In other words, the developer split the flag into two halves, encrypted each half, and stored them alongside the key — all inside the binary. The key to solving the challenge is right there in the file; we just needed to find it.

---

## Step 5 — Inspect the Static Constructor IL

Now we look at how the program initializes those four arrays when it starts. Every .NET class can have a special method called `.cctor` (short for **static constructor**). This method runs automatically the moment the program launches, before any user interaction happens, and its job is to set up static data.

IL stands for **Intermediate Language** — it is the low-level instruction format that C# compiles into. Think of it like the assembly instructions a chef writes down before cooking: very precise, one small action at a time. Reading IL lets us understand exactly what the program does step by step, even without the original source code.

Reading the `.cctor` method reveals the following sequence:

```
newarr byte[48] → InitializeArray(Field[8])  → stsfld XOR_KEY
newarr byte[24] → InitializeArray(Field[10]) → stsfld FLAG_A
newarr byte[24] → InitializeArray(Field[9])  → stsfld FLAG_B
newarr byte[32] → InitializeArray(Field[11]) → stsfld TARGET_HASH
```

Each line follows the same three-step pattern:

1. **`newarr byte[N]`** — allocate a new empty array of N bytes in memory.
2. **`InitializeArray(Field[X])`** — fill that array with the raw bytes stored in the binary at the location pointed to by Field[X].
3. **`stsfld NAME`** — save the filled array into a global variable so the rest of the program can access it.

So before the program ever prints "Enter Flag:", it has already quietly loaded all four arrays into memory. The encrypted flag halves and the decryption key are sitting in RAM, waiting. All we have to do now is read them and reverse the encryption.

---

## Step 6 — Decrypt the Flag

Now that we know the structure, decryption is straightforward. The program uses **XOR encryption**, one of the simplest and most common encryption methods you will encounter in CTF challenges.

XOR (eXclusive OR) is a basic operation that works on individual bits. The key property to understand is that XOR is **perfectly reversible**: if you XOR a value with a key to encrypt it, you XOR the encrypted result with the same key to get the original back. It is its own inverse, which makes it very convenient for simple encryption schemes.

A simple analogy: imagine you have a secret message and a key. You combine each letter of the message with the corresponding letter of the key to produce scrambled output. To unscramble it, you apply the key again in exactly the same way. XOR works identically, but with binary digits instead of letters.

The flag was split into two 24-byte halves, and each half was XOR'd with a different portion of the 48-byte key:

```
FLAG_A XOR XOR_KEY[0:24]   →   first half of the flag  (bytes 0 to 23 of the key)
FLAG_B XOR XOR_KEY[24:48]  →   second half of the flag (bytes 24 to 47 of the key)
```

To decrypt, we apply XOR again with the same key. In Python, the `^` symbol means XOR, and `zip()` pairs up the bytes of two arrays so we can process them one pair at a time:

```python
decrypted = bytes(a ^ k for a, k in zip(flag_a, xor_key[:24])) + \
            bytes(b ^ k for b, k in zip(flag_b, xor_key[24:]))

print(decrypted)
```

**Output:**
```
b'jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69'
```

The `b'...'` notation just means Python is displaying a sequence of bytes. The content inside is readable text — our candidate flag. It looks like a typical CTF flag written in leet-speak (where some letters are replaced with numbers that look similar, a common CTF style). Before submitting, we verify it properly.

---

## Step 7 — Verify the Result

The program does not compare your input directly against the plaintext flag. Instead, it computes the **SHA-256 hash** of whatever you type and checks it against `TARGET_HASH`.

A hash function is a one-way mathematical operation: it takes any input of any size and produces a fixed-size output (32 bytes for SHA-256) called a **digest** or **fingerprint**. The same input always produces the same output, but you cannot go backwards — you cannot figure out the original input just by looking at the hash. This is why storing a hash instead of the real flag is a common technique: it lets the program verify your answer without keeping the answer itself in plain sight in memory.

Since we already have the decrypted flag, we just hash it ourselves and confirm it matches what the program expects:

```python
import hashlib

hashlib.sha256(decrypted).digest() == TARGET_HASH
```

**Output:**
```
True
```

The hashes match exactly. To be completely certain, we run the original binary with our decrypted string:

```bash
$ ./rev_this_#.bin
Enter Flag: jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69
Access Granted!
```

The program accepts the flag. Challenge solved.

---

## Final Flag

```
jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69
```

---

**Author:** becem69
