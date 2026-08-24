#include <iostream>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static bool s_isRunning = true;

/**
 * Voodoo magic to keep function in the resulting binary even though it is unused.
 */
__declspec(dllexport) void stop() {
    s_isRunning = false;
}

int main() {
    std::cout << "Process ID: " << GetCurrentProcessId() << '\n';
    while (s_isRunning) {

    }
    std::cout << "Success!\n";
    return 0;
}
