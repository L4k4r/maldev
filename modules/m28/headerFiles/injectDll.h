#pragma once
#include <Windows.h>

BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName);