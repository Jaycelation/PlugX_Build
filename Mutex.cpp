#include <windows.h>
#include <iostream>
#include <conio.h>

int main() {
    const char* maliciousMutexName = "Global\\RATCTF{Testing_RAT_Mutex!!}";

    std::cout << "[*] Initializing malware..." << std::endl;
    std::cout << "[*] Attempting to create Mutex: " << maliciousMutexName << std::endl;

    HANDLE hMutex = CreateMutexA(NULL, TRUE, maliciousMutexName);

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[!] DETECTED: Mutex already exists!" << std::endl;
        std::cout << "[!] Another instance of the program is running." << std::endl;
        std::cout << "[!] This instance will self-destruct (Exit) to avoid conflict." << std::endl;
        
        if (hMutex) {
            CloseHandle(hMutex);
        }
        
        std::cout << "\nPress any key to exit...";
        _getch();
        return 1; 
    }

    std::cout << "[+] SUCCESS: Mutex created." << std::endl;
    std::cout << "[+] This is the main instance." << std::endl;
    std::cout << "[+] Executing malicious payload..." << std::endl;

    std::cout << "\n[Running] Program is running. Try opening another window..." << std::endl;
    
    while (!_kbhit()) {
        Sleep(1000); 
        std::cout << "."; 
    }

    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return 0;
}