# rev_this_#.bin - Reverse Engineering Writeup

**Event:** Ramadhan CTF organized at ISET'COM  
**Category:** Reverse Engineering  
**Binary:** `rev_this_#.bin` (ELF 64-bit, .NET 6 Self-Contained)  
**Flag:** `jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69`

---

## Table of Contents

1. [Overview](#overview)
2. [Tools Required](#tools-required)
3. [Step 1 - Identify the Binary](#step-1---identify-the-binary)
4. [Step 2 - Discover the Hidden .NET Bundle](#step-2---discover-the-hidden-net-bundle)
5. [Step 3 - Extract revproj.dll](#step-3---extract-revprojdll)
6. [Step 4 - Decompile the Managed Assembly](#step-4---decompile-the-managed-assembly)
7. [Step 5 - Understand the Program Logic](#step-5---understand-the-program-logic)
8. [Step 6 - Decrypt the Flag](#step-6---decrypt-the-flag)
9. [Step 7 - Verify the Result](#step-7---verify-the-result)
10. [Final Flag](#final-flag)

---

## Overview

Reverse engineering is the process of analyzing a compiled program without having its original source code. You only have the binary file the computer runs, and your job is to figure out what it does and extract hidden information in CTF challenges, that hidden information is called a **flag**.

This challenge presents a Linux ELF binary that looks ordinary from the outside. However, it is actually a **.NET 6 self-contained application**: a format where a C# program and the entire .NET runtime are packed together into a single file. The actual C# logic, including the encrypted flag, lives inside an embedded DLL hidden within the binary.

The attack path is:

```
ELF binary  ->  find embedded .NET bundle  ->  extract DLL  ->  decompile C#  ->  XOR decrypt  ->  flag
```
## Setup instructions
```bash
git clone https://github.com/becem69/Ramadhan-CTF-rev-this-sharp-challenge-writeup.git
7z x rev_this_#.bin.7z
```

**Key concepts covered:**

- ELF binary format identification
- .NET 6 single-file bundle structure
- Embedded PE/DLL extraction
- .NET assembly decompilation
- Runtime string obfuscation
- Anti-debugging techniques
- XOR encryption and decryption
- SHA-256 hash verification

---

## Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| `file` | Identify binary format | Pre-installed on Linux |
| `strings` | Search readable text in binaries | Pre-installed on Linux |
| `binwalk` | Detect embedded files | `sudo apt install binwalk` |
| `python3` | Scripting (extraction, decryption) | Pre-installed on most distros |
| `ilspycmd` | Decompile .NET assemblies | `dotnet tool install -g ilspycmd` |

---

## Step 1 - Identify the Binary

Before doing anything else, find out what kind of file you are dealing with. The `file` command reads the first few bytes (called **magic bytes**) and identifies the format.

```bash
file "rev_this_#.bin"
```

Output:

```
rev_this_#.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Breaking this down:

- **ELF** - the standard executable format on Linux (equivalent to `.exe` on Windows).
- **64-bit / x86-64** - compiled for modern 64-bit processors.
- **stripped** - all debug symbols and function names have been deliberately removed, making static analysis harder.

### Run it

```bash
chmod +x rev_this_#.bin
./rev_this_#.bin
```

```
Enter Flag:
Debugger Detected!
```

Two things stand out immediately:

1. **Anti-debugging trap** - the program detects whether a debugger or analysis tool is attached and immediately exits with "Debugger Detected!". This is a common protection in CTF challenges and real-world malware.
2. **Hidden strings** - if you search for "Enter Flag:" with `strings`, it does not appear. The developer stored all display strings as hex-encoded values and only decodes them at runtime. This is called **runtime string obfuscation**.

```bash
strings "rev_this_#.bin" | grep -i "flag"
# No output -- the string is hidden
```

### Spot the .NET clues

Even though interesting strings are obfuscated, `strings` still leaks .NET runtime artifacts:

```bash
strings "rev_this_#.bin" | grep -i "dotnet\|coreclr\|corehost\|netcore"
```

You will see references to `.NETCoreApp`, `hostfxr`, `System.Private.CoreLib`, and similar. These are signatures of a .NET self-contained application baked into the ELF.

---

## Step 2 - Discover the Hidden .NET Bundle

### What is a .NET 6 self-contained single-file app?

When you publish a C# program with `dotnet publish -r linux-x64 --self-contained -p:PublishSingleFile=true`, the .NET toolchain:

1. Compiles your C# code into a DLL.
2. Takes the entire .NET runtime (hundreds of DLLs).
3. Packs everything into one ELF binary using a bundle format.

From the outside it is just an ELF. On the inside, it is an ELF with a large binary blob appended: the **bundle**, which contains all the packed DLLs as a mini file system. Microsoft's runtime uses a hardcoded magic byte sequence to mark where this bundle starts.

### The fastest approach: binwalk

`binwalk` scans a binary for known file signatures and embedded structures. Run it first:

```bash
binwalk "rev_this_#.bin"
```

Expected output (abridged):

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB executable, AMD x86-64
10782512      0xA49730        PE32+ executable (DLL) (console), x86-64
```

`binwalk` directly tells you there is an embedded PE32+ DLL at file offset **0xA49730**. This is `revproj.dll`, the actual C# program. You now have the extraction offset without any manual searching.

### Manual approach: searching for the bundle magic bytes

If `binwalk` is unavailable, you can find the bundle manually. Microsoft's .NET runtime marks the start of the bundle header with a fixed 8-byte magic sequence:

```
8B 12 02 B9 6A 61 20 38
```

This constant is defined in the .NET runtime source code and never changes across versions. Use this Python script to find it:

```python
import struct

MAGIC = bytes([0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38])

with open("rev_this_#.bin", "rb") as f:
    data = f.read()

magic_off = data.find(MAGIC)
print(f"Magic bytes found at offset: 0x{magic_off:x}")

# The 8 bytes immediately before the magic contain a pointer to the bundle header
ptr_off = magic_off - 8
bundle_header_offset = struct.unpack_from('<Q', data, ptr_off)[0]
print(f"Bundle header offset: 0x{bundle_header_offset:x}")
```

Output:

```
Magic bytes found at offset: 0xa23018
Bundle header offset: 0x3d31529
```

An **offset** is just the distance from the start of the file in bytes. The bundle header is a directory that lists every file packed inside the binary, including its name, offset, and size.

### Finding the DLL entry in the bundle

Inside the bundle, each file entry is prefixed with metadata. The entry for the main C# DLL starts with:

```
\x01\x0b revproj.dll
```

| Byte | Meaning |
|------|---------|
| `0x01` | File type: managed assembly (a compiled .NET DLL) |
| `0x0b` | `11` in decimal: the length of the filename `revproj.dll` |

The 24 bytes before this marker contain the file's location and size:

| Field | Value |
|-------|-------|
| Offset inside binary | `0xa49730` |
| Size | `10240` bytes |
| Compressed size | `0` (stored uncompressed) |

These values match exactly what `binwalk` found.

---

## Step 3 - Extract revproj.dll

Now extract the DLL. Since it is stored uncompressed, simply read 10240 bytes from offset `0xa49730`:

```python
DLL_OFFSET = 0xa49730
DLL_SIZE   = 10240

with open("rev_this_#.bin", "rb") as f:
    f.seek(DLL_OFFSET)
    dll_data = f.read(DLL_SIZE)

# Verify: a valid PE/DLL always starts with the two bytes "MZ"
print(f"First 2 bytes: {dll_data[:2]}")   # Should print: b'MZ'

with open("revproj.dll", "wb") as out:
    out.write(dll_data)

print(f"Extracted {len(dll_data)} bytes -> revproj.dll")
```

Output:

```
First 2 bytes: b'MZ'
Extracted 10240 bytes -> revproj.dll
```

The `MZ` magic confirms this is a valid Windows PE file (Portable Executable). Even though it was buried inside a Linux ELF, the DLL itself uses the standard .NET/Windows format that all decompilers understand. You can also verify with:

```bash
file revproj.dll
# revproj.dll: PE32+ executable (DLL) (console) x86-64 Mono/.Net assembly
```

---

## Step 4 - Decompile the Managed Assembly

.NET DLLs compile to **IL (Intermediate Language)**, a CPU-independent bytecode. Unlike native binaries, IL is almost fully recoverable back to C# source code. Tools like `ilspycmd` (ILSpy command-line) do this automatically.

```bash
ilspycmd revproj.dll
```

This outputs the complete reconstructed C# source. The relevant class is `DynamicLabyrinth.Program`. The decompiled output is shown in full in the next step.

> If `ilspycmd` is not installed:
> ```bash
> dotnet tool install -g ilspycmd
> ```
> After installation, `ilspycmd` is available as a global command.

---

## Step 5 - Understand the Program Logic

Here is the full decompiled source, exactly as `ilspycmd` produces it:

```csharp
namespace DynamicLabyrinth
{
    internal class Program
    {
        // 48-byte XOR key used to encrypt/decrypt the flag
        private static readonly byte[] XOR_KEY = new byte[48]
        {
            90, 63, 113, 194, 136, 20, 173, 103, 43, 240,
            25, 78, 147, 124, 5, 184, 211, 42, 97, 250,
            56, 157, 84, 11, 231, 70, 140, 18, 127, 197,
            62, 161, 89, 132, 45, 107, 243, 23, 172, 112,
            219, 79, 146, 38, 232, 93, 3, 190
        };

        // First 24 bytes of the XOR-encrypted flag
        private static readonly byte[] FLAG_A = new byte[24]
        {
            48, 74, 2, 245, 215, 102, 158, 10, 24, 157,
            123, 125, 225, 35, 107, 136, 140, 73, 85, 138,
            103, 234, 60, 56
        };

        // Last 24 bytes of the XOR-encrypted flag
        private static readonly byte[] FLAG_B = new byte[24]
        {
            137, 25, 245, 34, 10, 154, 77, 209, 106, 232,
            65, 52, 196, 127, 159, 29, 132, 45, 247, 69,
            141, 48, 53, 135
        };

        // SHA-256 hash of the correct plaintext flag, used for verification
        private static readonly byte[] TARGET_HASH = new byte[32]
        {
            45, 181, 100, 88, 110, 53, 61, 154, 20, 22,
            173, 58, 124, 86, 90, 154, 94, 38, 187, 61,
            96, 151, 167, 90, 201, 86, 142, 153, 19, 126,
            133, 44
        };

        // All display strings stored as hex to hide them from `strings`
        private static readonly string[] ENC_STRINGS = new string[5]
        {
            "456e74657220466c61673a20",       // "Enter Flag: "
            "416363657373204772616e74656421", // "Access Granted!"
            "4163636573732044656e6965642e",   // "Access Denied."
            "446562756767657220446574656374656421", // "Debugger Detected!"
            "486173682047656e6572617465643a20"      // "Hash Generated: "
        };

        private static void Main(string[] args)
        {
            // Hidden dev mode: run with --gen to print the encrypted arrays
            if (args.Length != 0 && args[0] == "--gen")
            {
                string s = DecryptFlag();
                // ... prints FLAG_A, FLAG_B, TARGET_HASH values
            }
            else
            {
                RunChallenge();
            }
        }

        private static string DecryptFlag()
        {
            // Concatenate FLAG_A + FLAG_B, then XOR each byte with XOR_KEY[i % 48]
            byte[] bytes = FLAG_A.Concat(FLAG_B)
                .ToArray()
                .Select((byte b, int i) => (byte)(b ^ XOR_KEY[i % XOR_KEY.Length]))
                .ToArray();
            return Encoding.UTF8.GetString(bytes);
        }

        private static void RunChallenge()
        {
            // Anti-debug check: if a debugger is attached, print "Debugger Detected!" and exit
            if (Debugger.IsAttached)
            {
                Console.WriteLine(DecryptHex(ENC_STRINGS[3]));
                Environment.Exit(1);
            }

            // Timing check: if the user takes more than 5 seconds to type, also exit
            long ticks = DateTime.Now.Ticks;
            Console.Write(DecryptHex(ENC_STRINGS[0]));  // "Enter Flag: "
            string text = Console.ReadLine();
            if (DateTime.Now.Ticks - ticks > 50000000)
            {
                Console.WriteLine(DecryptHex(ENC_STRINGS[3]));
                Environment.Exit(1);
            }

            // Build and run the validator dynamically at runtime (makes static analysis harder)
            if (BuildDynamicValidator()(text))
                Console.WriteLine(DecryptHex(ENC_STRINGS[1]));  // "Access Granted!"
            else
                Console.WriteLine(DecryptHex(ENC_STRINGS[2]));  // "Access Denied."
        }

        private static string DecryptHex(string hex)
        {
            // Convert hex string -> bytes -> UTF-8 string
            byte[] array = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                array[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return Encoding.UTF8.GetString(array);
        }

        private static Func<string, bool> BuildDynamicValidator()
        {
            // Builds a method at runtime using IL emission that:
            // 1. Takes the user's input string
            // 2. Computes SHA-256(UTF8(input))
            // 3. Compares the hash byte-by-byte against TARGET_HASH
            // This makes the validation logic invisible to static decompilers
            DynamicMethod dynamicMethod = new DynamicMethod(
                "ValidateInput", typeof(bool), new Type[] { typeof(string) },
                typeof(Program).Module);
            ILGenerator il = dynamicMethod.GetILGenerator();
            // ... emits: SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(input))
            // ... then calls CompareHashes(TARGET_HASH, computed_hash)
            return (Func<string, bool>)dynamicMethod.CreateDelegate(typeof(Func<string, bool>));
        }

        private static bool CompareHashes(byte[] expected, byte[] actual)
        {
            if (expected.Length != actual.Length) return false;
            for (int i = 0; i < expected.Length; i++)
                if (expected[i] != actual[i]) return false;
            return true;
        }
    }
}
```

### Protections summary

| Protection | How it works | How we bypass it |
|------------|-------------|-----------------|
| Stripped ELF | No function names in the binary | Irrelevant once we decompile the DLL |
| String obfuscation | Strings stored as hex, decoded at runtime | Decoded manually or visible after decompilation |
| Anti-debug (`Debugger.IsAttached`) | Exits if a debugger is attached | We never run it under a debugger |
| Timing check (5 seconds) | Exits if input takes too long | We never interact with it live |
| Dynamic validator (`DynamicMethod`) | Validation logic built at runtime | Irrelevant; we can read `TARGET_HASH` and `DecryptFlag()` directly |

### The encryption scheme

The flag was split into two 24-byte halves and XOR-encrypted:

```
plaintext[0..23]  XOR XOR_KEY[0..23]  = FLAG_A
plaintext[24..47] XOR XOR_KEY[24..47] = FLAG_B
```

XOR is its own inverse. To decrypt: apply XOR again with the same key.

```
FLAG_A XOR XOR_KEY[0..23]   = plaintext[0..23]
FLAG_B XOR XOR_KEY[24..47]  = plaintext[24..47]
```

The program never stores the plaintext flag. Instead it stores `TARGET_HASH = SHA256(plaintext)` and verifies the user's input by hashing it and comparing. This means the flag is protected even from memory dumping during runtime.

---

## Step 6 - Decrypt the Flag

All four arrays are now known from the decompiled source. The decryption is a direct translation of `DecryptFlag()` into Python:

```python
import hashlib

XOR_KEY = bytes([
    90, 63, 113, 194, 136, 20, 173, 103, 43, 240,
    25, 78, 147, 124, 5, 184, 211, 42, 97, 250,
    56, 157, 84, 11, 231, 70, 140, 18, 127, 197,
    62, 161, 89, 132, 45, 107, 243, 23, 172, 112,
    219, 79, 146, 38, 232, 93, 3, 190
])

FLAG_A = bytes([
    48, 74, 2, 245, 215, 102, 158, 10, 24, 157,
    123, 125, 225, 35, 107, 136, 140, 73, 85, 138,
    103, 234, 60, 56
])

FLAG_B = bytes([
    137, 25, 245, 34, 10, 154, 77, 209, 106, 232,
    65, 52, 196, 127, 159, 29, 132, 45, 247, 69,
    141, 48, 53, 135
])

TARGET_HASH = bytes([
    45, 181, 100, 88, 110, 53, 61, 154, 20, 22,
    173, 58, 124, 86, 90, 154, 94, 38, 187, 61,
    96, 151, 167, 90, 201, 86, 142, 153, 19, 126,
    133, 44
])

# Concatenate the two halves, then XOR each byte with the key cycling by index
combined  = FLAG_A + FLAG_B
decrypted = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(combined))

print(f"Decrypted flag : {decrypted.decode('utf-8')}")

# Verify: SHA256 of the decrypted flag must match TARGET_HASH
digest = hashlib.sha256(decrypted).digest()
print(f"SHA-256 match  : {digest == TARGET_HASH}")
```

Output:

```
Decrypted flag : jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69
SHA-256 match  : True
```

### Why XOR decryption is this simple

XOR has one special property: `A XOR K XOR K = A`. If you XOR a value with a key to encrypt it, XORing the result with the same key perfectly undoes the operation. There is no second step, no padding, no IV. This makes it trivial to reverse as long as you have the key, which is sitting right there in the binary.

---

## Step 7 - Verify the Result

The final confirmation is running the actual binary with the recovered flag:

```bash
echo "jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69" | "./rev_this_#.bin"
```

Output:

```
Enter Flag: Access Granted!
```

The program accepts it. The SHA-256 hash of our decrypted string matches `TARGET_HASH` stored in the binary, so `CompareHashes` returns `true` and the program prints "Access Granted!".

---

## Final Flag

```
jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69
```

---

## Full Script (All-in-One)

Save this as `solve.py` in the same directory as `rev_this_#.bin` and run `python3 solve.py`:

```python
#!/usr/bin/env python3
"""
Solver for rev_this_#.bin
Ramadhan CTF - Reverse Engineering challenge
"""

import struct
import hashlib
import subprocess
import os

BINARY = "rev_this_#.bin"
DLL_OUT = "revproj.dll"

# ── Step 1: Find the .NET bundle magic and bundle header ──────────────────────

BUNDLE_MAGIC = bytes([0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38])

print("[*] Reading binary...")
with open(BINARY, "rb") as f:
    data = f.read()

magic_off = data.find(BUNDLE_MAGIC)
if magic_off == -1:
    raise RuntimeError("Bundle magic not found -- is this a .NET single-file app?")

print(f"[+] Bundle magic at offset : 0x{magic_off:x}")

bundle_header_off = struct.unpack_from('<Q', data, magic_off - 8)[0]
print(f"[+] Bundle header offset   : 0x{bundle_header_off:x}")

# ── Step 2: Extract revproj.dll ───────────────────────────────────────────────

# Offsets extracted from bundle header (confirmed by binwalk)
DLL_OFFSET = 0xa49730
DLL_SIZE   = 10240

dll_data = data[DLL_OFFSET : DLL_OFFSET + DLL_SIZE]

if dll_data[:2] != b'MZ':
    raise RuntimeError(f"Expected MZ header at 0x{DLL_OFFSET:x}, got {dll_data[:2]}")

with open(DLL_OUT, "wb") as f:
    f.write(dll_data)

print(f"[+] Extracted {DLL_SIZE} bytes to {DLL_OUT} (magic: MZ confirmed)")

# ── Step 3: Decrypt the flag (values read directly from decompiled source) ─────

XOR_KEY = bytes([
    90, 63, 113, 194, 136, 20, 173, 103, 43, 240,
    25, 78, 147, 124, 5, 184, 211, 42, 97, 250,
    56, 157, 84, 11, 231, 70, 140, 18, 127, 197,
    62, 161, 89, 132, 45, 107, 243, 23, 172, 112,
    219, 79, 146, 38, 232, 93, 3, 190
])

FLAG_A = bytes([
    48, 74, 2, 245, 215, 102, 158, 10, 24, 157,
    123, 125, 225, 35, 107, 136, 140, 73, 85, 138,
    103, 234, 60, 56
])

FLAG_B = bytes([
    137, 25, 245, 34, 10, 154, 77, 209, 106, 232,
    65, 52, 196, 127, 159, 29, 132, 45, 247, 69,
    141, 48, 53, 135
])

TARGET_HASH = bytes([
    45, 181, 100, 88, 110, 53, 61, 154, 20, 22,
    173, 58, 124, 86, 90, 154, 94, 38, 187, 61,
    96, 151, 167, 90, 201, 86, 142, 153, 19, 126,
    133, 44
])

combined  = FLAG_A + FLAG_B
decrypted = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(combined))
flag      = decrypted.decode('utf-8')

print(f"[+] Decrypted flag         : {flag}")

# ── Step 4: Verify SHA-256 ────────────────────────────────────────────────────

digest = hashlib.sha256(decrypted).digest()
if digest == TARGET_HASH:
    print("[+] SHA-256 hash           : MATCH -- flag is correct")
else:
    print("[-] SHA-256 hash           : MISMATCH -- something went wrong")
    print(f"    Got      : {digest.hex()}")
    print(f"    Expected : {TARGET_HASH.hex()}")

# ── Step 5: Confirm with the actual binary ────────────────────────────────────

print("\n[*] Testing against the binary...")
result = subprocess.run(
    [f"./{BINARY}"],
    input=flag,
    capture_output=True,
    text=True
)
output = result.stdout.strip()
print(f"[+] Binary output          : {output}")

if "Access Granted" in output:
    print(f"\n[*] FLAG: {flag}")
else:
    print("\n[-] Binary did not accept the flag.")

# ── Cleanup ───────────────────────────────────────────────────────────────────

os.remove(DLL_OUT)
print("[*] Cleaned up revproj.dll")
```

---

## Key Takeaways

- **.NET single-file apps on Linux** are ELF binaries with an embedded bundle. `binwalk` will instantly reveal any PE/DLL inside.
- **The .NET bundle magic** `8B 12 02 B9 6A 61 20 38` is a fixed constant in the .NET runtime source. Recognizing it saves a lot of time.
- **IL decompilation is nearly lossless.** `ilspycmd` recovers readable C# from a DLL with no source available. Always try decompilation before manual binary analysis.
- **Static analysis beats every runtime protection here.** The anti-debug check, timing check, and dynamically emitted validator are all irrelevant when you read the data straight from the DLL without ever executing it.
- **XOR with a hardcoded key is not encryption.** The key is in the binary. Once you find it, decryption is a one-liner.
- **Storing a hash instead of the plaintext** does not help if the attacker can read the decrypt routine from the decompiled source.

 
---


## Author
**becem69 😝**
