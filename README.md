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
- [Final Flag](#-final-flag)

---

## Overview

This repository contains the solution walkthrough for **rev_this_#.bin**, a reverse engineering challenge from **Ramadhan CTF organized at ISET'COM**.

The binary is a Linux ELF executable that embeds a **.NET 6 self-contained assembly**. The flag is hidden inside a `.NET DLL` bundled within the ELF, encrypted using XOR and verified with SHA-256.

**Key concepts covered:**
- ELF binary analysis
- .NET single-file bundle extraction
- .NET metadata stream parsing (#US, FieldRVA)
- XOR decryption
- SHA-256 hash verification

---

## Step 1 — Identify the Binary

Run the `file` command to identify the binary type:

```bash
file rev_this_#.bin
```

**Output:**
```
rev_this_#.bin: ELF 64-bit LSB executable, x86-64, stripped
```

Running the binary reveals:
```
Enter Flag:
Debugger Detected!
```

> **Note:** These strings do **not** appear in the normal `strings` output — they are hex-encoded and decoded at runtime as an obfuscation technique.

---

## Step 2 — Find the .NET Bundle

.NET 6 **self-contained single-file applications** embed all assemblies inside the ELF binary. The bundle is located by searching for the magic bytes:

```
8B 12 02 B9 6A 61 20 38
```

This signature marks the **.NET bundle header**.

| Item | Value |
|------|-------|
| Magic bytes offset | `0xa23018` |
| Bundle header pointer (8 bytes before magic) | `0x3d31529` |

---

## Step 3 — Extract revproj.dll

Inside the bundle table, search for the entry:

```
\x01\x0brevproj.dll
```

| Byte | Meaning |
|------|---------|
| `0x01` | Managed assembly (file type) |
| `0x0b` | `11` — length of filename `revproj.dll` |

The **24 bytes preceding the entry** provide the file metadata:

| Field | Value |
|-------|-------|
| Offset | `0xa49730` |
| Size | `10240` bytes |
| Compressed size | `0` (not compressed) |

Since the file is not compressed, extracting **10240 bytes** from offset `0xa49730` yields a valid **PE/MZ file** — `revproj.dll`.

---

## Step 4 — Analyze the Managed Assembly

Parse the **.NET metadata streams** inside the extracted DLL:

```
#~        ← tables stream (methods, fields, types)
#Strings  ← identifier names
#US       ← User Strings heap (string literals)
#Blob     ← binary data blobs
```

### String Obfuscation

From the **#US (User Strings)** heap, runtime strings are stored as hex:

```
456e74657220466c61673a20        →   "Enter Flag:"
416363657373204772616e74656421  →   "Access Granted!"
```

### Static Byte Arrays (FieldRVA Table)

Four static byte arrays were identified:

| Field | Size | Purpose |
|-------|------|---------|
| `Field[8]` | 48 bytes | `XOR_KEY` |
| `Field[10]` | 24 bytes | `FLAG_A` (encrypted) |
| `Field[9]` | 24 bytes | `FLAG_B` (encrypted) |
| `Field[11]` | 32 bytes | `TARGET_HASH` (SHA-256) |

---

## Step 5 — Inspect the Static Constructor IL

Reading the `.cctor` method reveals how the arrays are initialized at startup:

```
newarr byte[48] → InitializeArray(Field[8])  → stsfld XOR_KEY
newarr byte[24] → InitializeArray(Field[10]) → stsfld FLAG_A
newarr byte[24] → InitializeArray(Field[9])  → stsfld FLAG_B
newarr byte[32] → InitializeArray(Field[11]) → stsfld TARGET_HASH
```

The program loads **static encrypted data** before asking for user input.

---

## Step 6 — Decrypt the Flag

The flag is reconstructed by **XOR-decrypting two encrypted blocks** with the corresponding halves of the key:

```
FLAG_A XOR XOR_KEY[0:24]   →   first half of flag
FLAG_B XOR XOR_KEY[24:48]  →   second half of flag
```

**Python implementation:**

```python
decrypted = bytes(a ^ k for a, k in zip(flag_a, xor_key[:24])) + \
            bytes(b ^ k for b, k in zip(flag_b, xor_key[24:]))

print(decrypted)
```

**Output:**
```
b'jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69'
```

---

## Step 7 — Verify the Result

The program verifies the flag by comparing its **SHA-256 hash** with `TARGET_HASH`:

```python
import hashlib

hashlib.sha256(decrypted).digest() == TARGET_HASH
```

**Output:**
```
True
```

Running the binary confirms:

```bash
$ ./rev_this_#.bin
Enter Flag: jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69
Access Granted!
```

---

## Final Flag

```
jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69
```

---

**Author:** becem69
