#pragma once

#include <Windows.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

BOOL GenerateRandomBytes(PUCHAR Buffer, DWORD Length);
BOOL EncryptAES(PUCHAR Plaintext, DWORD PlaintextSize, PUCHAR Key, PUCHAR IV, PUCHAR* Ciphertext, DWORD* CiphertextSize);

void PrintHex(const char* Name, BYTE* Buffer, DWORD Size);