#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

extern "C" __declspec(dllexport) void ExpectedFunction() {
    
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    const char* logFile = "C:\\Temp\\Malware_Activity.log";
    std::ofstream log(logFile, std::ios_base::app | std::ios_base::out);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);

        log << "==========================================================" << std::endl;
        log << "[ALERT] MALICIOUS DLL LOADED!" << std::endl;
        log << "Process: " << GetCommandLineA() << std::endl;
        log << "DLL Name: Malicious.dll (Side-Loaded)" << std::endl;
        log << "Timestamp: " << __DATE__ << " " << __TIME__ << std::endl;
        log << "Payload Action: Created persistence log file in C:\\Temp" << std::endl;
        log << "==========================================================" << std::endl;
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    
    log.close();
    return TRUE;
}