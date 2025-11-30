# Classic Process Injection (Shellcode Injection)

**Classic Process Injection** is a common attack technique used by malware (such as PlugX, Cobalt Strike) to execute malicious code within the memory space of a legitimate process (e.g., `notepad.exe`, `explorer.exe`).

## Purpose
1.  **Evasion:** Avoid detection in Task Manager (users only see `notepad.exe` running).
2.  **Bypass Firewall:** Exploit clean processes that are allowed to connect to the Internet to send data out (C2).
3.  **Privilege Escalation:** Inherit the privileges of the injected process.

---

## Operating Mechanism (4 Main Steps)

This process relies on core Windows API functions:

1.  **Targeting (Create/Open Process):**
    * Use `CreateProcessA` (to create new) or `OpenProcess` (to open running process).
    * Goal: Obtain a **Handle** to manage the victim process.

2.  **Allocation:**
    * Use `VirtualAllocEx`.
    * **Crucial Note:** Must request `PAGE_EXECUTE_READWRITE` (**RWX**) permission to allow both writing data and executing code. This is a major IOC.

3.  **Writing Payload:**
    * Use `WriteProcessMemory`.
    * Copy the **Shellcode** (machine code) from the malware file to the newly allocated memory of the victim.

4.  **Execution:**
    * Use `CreateRemoteThread`.
    * Create a new thread in the victim process, pointing the Start Address to the location containing the Shellcode.

---

## Demo Source Code

Refer to file: [ClassicInjection.cpp](ClassicInjection.cpp)

---

## IOCs (Indicators for Blue Team)

EDR/Antivirus systems will look for the following behavioral sequence:

* **API Call Sequence:** `VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread`.
* **Memory Permission:** A process requesting **RWX** (`PAGE_EXECUTE_READWRITE`) in another process.
* **Unbacked Memory:** Code executed in a memory region not backed by any file on disk (Memory-based threat).