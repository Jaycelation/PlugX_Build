#include <iostream>
#include <windows.h>
#include <chrono>

#define THRESHOLD_MS 50 

void PerformAntiDebugAction() {
    std::cout << "[!] ANTI-DEBUGGING DETECTED: Execution time is inconsistent!" << std::endl;
    std::cout << "[!] Malware will terminate itself or proceed with a dummy payload." << std::endl;
}

void ContinueExecution() {
    std::cout << "[+] NO DEBUGGER DETECTED. Proceeding with legitimate execution..." << std::endl;
}

int main() {
    ULONGLONG t1 = GetTickCount64();

    for (int i = 0; i < 1000; ++i) {
        volatile int dummy = i * 2 + 1; 
        if (i == 500) {
            DWORD pid = GetCurrentProcessId(); 
        }
    }
    
    ULONGLONG t2 = GetTickCount64();

    ULONGLONG ElapsedTime = t2 - t1;

    std::cout << "------------------------------------------" << std::endl;
    std::cout << "Code execution time: " << ElapsedTime << " ms" << std::endl;
    
    if (ElapsedTime > THRESHOLD_MS) {
        PerformAntiDebugAction();
    } else {
        ContinueExecution();
    }
    std::cout << "------------------------------------------" << std::endl;

    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}