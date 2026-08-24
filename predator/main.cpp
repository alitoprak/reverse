#include <iostream>
#include <vector>
#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void* ScanPattern(HANDLE processHandle, const std::vector<int>& pattern) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPCVOID currentAddress = sysInfo.lpMinimumApplicationAddress;
    LPCVOID maxAddress = sysInfo.lpMaximumApplicationAddress;

    while (currentAddress < maxAddress) {
        MEMORY_BASIC_INFORMATION memoryInfo;
        if (VirtualQueryEx(processHandle, currentAddress, &memoryInfo, sizeof(memoryInfo)) == 0) {
            break;
        }

        bool isCommitted = memoryInfo.State == MEM_COMMIT;
        bool isAccessible = (memoryInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        bool isNotGuarded = (memoryInfo.Protect & PAGE_GUARD) == 0;

        LPCVOID nextAddress = static_cast<const BYTE*>(memoryInfo.BaseAddress) + memoryInfo.RegionSize;

        if (isCommitted && isAccessible && isNotGuarded) {
            std::vector<BYTE> localBuffer(memoryInfo.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(processHandle, memoryInfo.BaseAddress, localBuffer.data(), memoryInfo.RegionSize, &bytesRead)) {
                auto match = std::search(
                    localBuffer.begin(), localBuffer.begin() + bytesRead,
                    pattern.begin(), pattern.end(),
                    [](BYTE bufferByte, int patternByte) {
                        return patternByte == -1 || bufferByte == patternByte;
                    }
                );

                if (match != localBuffer.begin() + bytesRead) {
                    uintptr_t offset = std::distance(localBuffer.begin(), match);
                    uintptr_t targetAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + offset;
                    return reinterpret_cast<void*>(targetAddress);
                }
            }
        }

        currentAddress = nextAddress;
    }

    return nullptr;
}

int main() {
    DWORD processId;
    std::cout << "Enter process id: ";
    std::cin >> processId;

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (processHandle == nullptr) {
        std::cout << "Failed to open process!\n";
        return 1;
    }

    std::vector<int> pattern = {
        0x40, 0x57, // push rdi
        0xC6, 0x05 // mov byte ptr [rip + offset], imm8
    };
    void* result = ScanPattern(processHandle, pattern);

    if (result != nullptr) {
        std::cout << "Pattern found at: " << result << '\n';

        HANDLE hThread = CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(result),
            nullptr,
            0,
            nullptr
        );

        if (hThread != nullptr) {
            std::cout << "Successfully executed the function in the target process!\n";

            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        } else {
            std::cout << "Failed to create remote thread. Error: " << GetLastError() << '\n';
        }
    } else {
        std::cout << "Pattern not found.\n";
    }

    CloseHandle(processHandle);
    return 0;
}