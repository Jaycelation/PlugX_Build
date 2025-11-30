#include <windows.h>
#include <iostream>

typedef void (*ExpectedFuncPtr)();

int main() {
    std::cout << "[LegitimateApp.exe] Starting execution..." << std::endl;
    
    const char* dllName = "MyLibrary.dll"; 

    HMODULE hDll = LoadLibraryA(dllName); 

    if (hDll != NULL) {
        std::cout << "[LegitimateApp.exe] Successfully loaded DLL: " << dllName << std::endl;

        ExpectedFuncPtr func = (ExpectedFuncPtr)GetProcAddress(hDll, "ExpectedFunction");

        if (func != NULL) {
            std::cout << "[LegitimateApp.exe] Found ExpectedFunction. Calling..." << std::endl;
            func();
        } else {
            std::cout << "[LegitimateApp.exe] Error: Could not find ExpectedFunction in DLL." << std::endl;
        }

        FreeLibrary(hDll);
    } else {
        std::cout << "[LegitimateApp.exe] Error: Could not load DLL: " << dllName << " (Error code: " << GetLastError() << ")" << std::endl;
    }

    std::cout << "[LegitimateApp.exe] Finished execution." << std::endl;
    std::cin.get();
    return 0;
}