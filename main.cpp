#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <Psapi.h>
#include <TlHelp32.h>
#include <locale>
#include <codecvt>
#include <thread>

bool cleaned;

std::vector<LPVOID> FindStringAddressesByOrder(DWORD processId, const std::string& sequence) {
    std::vector<LPVOID> addresses;
    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle == NULL) {
        std::cout << "Failed to open the process." << std::endl;
        return addresses;
    }
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    LPVOID baseAddress = systemInfo.lpMinimumApplicationAddress;
    LPVOID maxAddress = systemInfo.lpMaximumApplicationAddress;
    std::string lowercaseSequence = sequence;
    std::transform(lowercaseSequence.begin(), lowercaseSequence.end(), lowercaseSequence.begin(), ::tolower);
    while (baseAddress < maxAddress) {
        MEMORY_BASIC_INFORMATION memoryInfo;
        if (VirtualQueryEx(processHandle, baseAddress, &memoryInfo, sizeof(memoryInfo)) == 0) {
            break;
        }
        if (memoryInfo.State == MEM_COMMIT && memoryInfo.Protect != PAGE_NOACCESS && memoryInfo.Protect != PAGE_GUARD) {
            const size_t bufferSize = memoryInfo.RegionSize;
            std::vector<char> buffer(bufferSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, &buffer[0], bufferSize, &bytesRead)) {
                std::string memoryString(buffer.begin(), buffer.end());
                std::transform(memoryString.begin(), memoryString.end(), memoryString.begin(), ::tolower);
                size_t foundIndex = memoryString.find(lowercaseSequence);
                while (foundIndex != std::string::npos) {
                    LPVOID stringAddress = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(memoryInfo.BaseAddress) + foundIndex);
                    addresses.push_back(stringAddress);
                    foundIndex = memoryString.find(lowercaseSequence, foundIndex + 1);
                }
            }
        }
        baseAddress = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(baseAddress) + memoryInfo.RegionSize);
    }
    CloseHandle(processHandle);
    return addresses;
}

std::vector<LPVOID> FindWStringAddressesByOrder(DWORD processId, const std::wstring& sequence) {
    std::vector<LPVOID> addresses;
    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle == NULL) {
        std::cout << "Failed to open the process." << std::endl;
        return addresses;
    }
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    LPVOID baseAddress = systemInfo.lpMinimumApplicationAddress;
    LPVOID maxAddress = systemInfo.lpMaximumApplicationAddress;
    std::wstring lowercaseSequence = sequence;
    std::transform(lowercaseSequence.begin(), lowercaseSequence.end(), lowercaseSequence.begin(), ::towlower);
    while (baseAddress < maxAddress) {
        MEMORY_BASIC_INFORMATION memoryInfo;
        if (VirtualQueryEx(processHandle, baseAddress, &memoryInfo, sizeof(memoryInfo)) == 0) {
            break;
        }
        if (memoryInfo.State == MEM_COMMIT && memoryInfo.Protect != PAGE_NOACCESS && memoryInfo.Protect != PAGE_GUARD) {
            const size_t bufferSize = memoryInfo.RegionSize;
            std::vector<wchar_t> buffer(bufferSize / sizeof(wchar_t));
            SIZE_T bytesRead;
            if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, &buffer[0], bufferSize, &bytesRead)) {
                std::wstring memoryString(buffer.begin(), buffer.end());
                std::transform(memoryString.begin(), memoryString.end(), memoryString.begin(), ::towlower);
                size_t foundIndex = memoryString.find(lowercaseSequence);
                while (foundIndex != std::wstring::npos) {
                    LPVOID stringAddress = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(memoryInfo.BaseAddress) + (foundIndex * sizeof(wchar_t)));
                    addresses.push_back(stringAddress);
                    foundIndex = memoryString.find(lowercaseSequence, foundIndex + 1);
                }
            }
        }
        baseAddress = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(baseAddress) + memoryInfo.RegionSize);
    }
    CloseHandle(processHandle);
    return addresses;
}

std::wstring StringToWideString(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

bool RemoveStringFromProcess(DWORD processId, const std::string& sequence, HANDLE processHandle) {
    std::vector<LPVOID> addresses = FindStringAddressesByOrder(processId, sequence);
    for (const auto& address : addresses) {
        if (WriteProcessMemory(processHandle, address, "", 1, NULL) == 0) {
            std::cout << "Failed to remove 0x" << std::hex << (int)(address) << " from the process." << std::endl;
        }
        else {
            cleaned = true;
        }
    }
    std::wstring wsequence = StringToWideString(sequence);
    std::vector<LPVOID> waddresses = FindWStringAddressesByOrder(processId, wsequence);
    for (const auto& waddress : waddresses) {
        if (WriteProcessMemory(processHandle, waddress, L"", 1, NULL) == 0) {
            std::cout << "Failed to remove 0x" << std::hex << (int)(waddress) << " from the process." << std::endl;
        }
        else {
            cleaned = true;
        }
    }
    return cleaned;
}

BOOL EnablePrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

int main() {
    EnablePrivilege();
    SetConsoleTitle("String Cleaner");

    DWORD processId;
    std::cout << "Enter the process ID: ";
    std::cin >> processId;

    std::string sequence;
    std::cout << "Enter the string sequence to remove: ";
    std::cin >> sequence;

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (processHandle == NULL) {
        std::cout << "Failed to open the process" << std::endl;
        return 1;
    }

    bool success = RemoveStringFromProcess(processId, sequence, processHandle);
    if (success) {
        std::cout << "String removed successfully" << std::endl;
    }
    else {
        std::cout << "Failed to remove the string" << std::endl;
    }

    CloseHandle(processHandle);
    Sleep(5000);

    return 0;
}
