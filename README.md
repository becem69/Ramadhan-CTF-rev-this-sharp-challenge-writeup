# Ramadhan-CTF-rev-this-#-challenge-writeup
# rev_this_#.bin — Reverse Engineering Challenge (Ramadhan CTF @ ISET'COM)

This repository contains the solution walkthrough for **rev_this_#.bin**, a reverse engineering challenge from **Ramadhan CTF organized at ISET'COM**.

---

## Step 1 — Identify the Binary

```bash
(becem69㉿becemNoCap)-[~]
└─$ file rev_this_#.bin
```

Output:

```
rev_this_#.bin: ELF 64-bit LSB executable, x86-64, stripped
```

Running the binary shows:

```
Enter Flag:
Debugger Detected!
```

However, these strings do **not appear in the normal `strings` output**, meaning they are **decoded or generated at runtime**.

---

## Step 2 — Find the .NET Bundle

.NET 6 **self-contained single-file applications** embed all assemblies inside the ELF binary.

The bundle can be located by searching for the magic bytes:

```
8B 12 02 B9 6A 61 20 38
```

This signature marks the **.NET bundle header**.

The sequence was found at offset:

```
0xa23018
```

The **8 bytes before this marker** point to the bundle header location:

```
0x3d31529
```

---

## Step 3 — Extract `revproj.dll`

Inside the bundle table we search for the entry:

```
\x01\x0brevproj.dll
```

Where:

* `0x01` = managed assembly
* `0x0b` = length of the filename (11)

The **24 bytes preceding the entry** provide metadata about the embedded file:

* **offset** = `0xa49730`
* **size** = `10240`
* **compressed_size** = `0`

Since the file is not compressed, extracting **10240 bytes** from the offset yields a valid **PE/MZ file**:

```
revproj.dll
```

---

## Step 4 — Analyze the Managed Assembly

Next step is parsing the **.NET metadata streams** inside the DLL:

```
#~
#Strings
#US
#Blob
```

From the **#US (User Strings)** heap we observe that runtime strings are **hex-encoded**.

Examples:

```
456e74657220466c61673a20
→ Enter Flag:

416363657373204772616e74656421
→ Access Granted!
```

From the **FieldRVA table**, four static byte arrays were identified:

| Field     | Size     | Purpose              |
| --------- | -------- | -------------------- |
| Field[8]  | 48 bytes | XOR_KEY              |
| Field[10] | 24 bytes | FLAG_A (encrypted)   |
| Field[9]  | 24 bytes | FLAG_B (encrypted)   |
| Field[11] | 32 bytes | TARGET_HASH (SHA256) |

---

## Step 5 — Inspect the Static Constructor IL

Reading the `.cctor` method reveals how the arrays are initialized.

```
newarr byte[48] → InitializeArray(Field[8]) → stsfld XOR_KEY
newarr byte[24] → InitializeArray(Field[10]) → stsfld FLAG_A
newarr byte[24] → InitializeArray(Field[9])  → stsfld FLAG_B
newarr byte[32] → InitializeArray(Field[11]) → stsfld TARGET_HASH
```

This shows the program loads **static encrypted data** at startup.

---

## Step 6 — Decrypt the Flag

The flag is constructed by **XOR-decrypting two encrypted blocks** using the XOR key.

```
FLAG_A XOR XOR_KEY[0:24]
+
FLAG_B XOR XOR_KEY[24:48]
```

Python example:

```python
decrypted = bytes(a ^ k for a, k in zip(flag_a, xor_key[:24])) + \
            bytes(b ^ k for b, k in zip(flag_b, xor_key[24:]))
```

Output:

```
b'jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69'
```

---

## Step 7 — Verify the Result

The program verifies the flag by comparing its **SHA256 hash** with `TARGET_HASH`.

```python
import hashlib

hashlib.sha256(decrypted).digest() == TARGET_HASH
```

Output:

```
True
```

Running the binary with the decrypted string confirms the result:

```
Access Granted!
```

---

# Final Flag

```
jus7_r3m3mb3r_n0_c4p_wh3n_y0u_sp3ll_7h3m_becem69
```
**Author : becem69**
