#include "encryption.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

BOOL GenerateRandomBytes(
	PUCHAR Buffer,
	DWORD Length
) {
	return BCryptGenRandom(
		NULL,
		Buffer,
		Length,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	) == EXIT_SUCCESS;
}

BOOL EncryptAES(PUCHAR Plaintext, DWORD PlaintextSize, PUCHAR Key, PUCHAR IV, PUCHAR* Ciphertext, DWORD* CiphertextSize) {

	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	DWORD dataSize = 0;
	DWORD keyObjectSize = 0;

	PUCHAR keyObject = NULL;
	NTSTATUS status = 0;


	// Open algoritm provider
	status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0
	);
	if (status != 0) return FALSE;

	// Get key object size
	status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&keyObjectSize,
		sizeof(DWORD),
		&dataSize,
		0
	);
	if (status != 0) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return FALSE;
	}

	keyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyObjectSize);
	if (!keyObject) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return FALSE;
	}

	// Generate key object
	status = BCryptGenerateSymmetricKey(
		hAlg,
		&hKey,
		keyObject,
		keyObjectSize,
		Key,
		AES_KEY_SIZE,
		0
	);
	if (status != 0) {
		HeapFree(GetProcessHeap(), 0, keyObject);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return FALSE;
	}

	// Make a local copy of the IV
	unsigned char ivCopy[AES_IV_SIZE];
	memcpy(ivCopy, IV, AES_IV_SIZE);

	// Pass 1: Query the required output buffer size
	status = BCryptEncrypt(
		hKey,
		Plaintext,
		PlaintextSize,
		NULL,
		ivCopy,
		AES_IV_SIZE,
		NULL,		// NULL buffer retrieves the required size
		0,
		&dataSize, // Receives required data size
		BCRYPT_BLOCK_PADDING
	);
	if (status != 0) {
	
		HeapFree(GetProcessHeap(), 0, keyObject);
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return FALSE;
	}

	*Ciphertext = (PUCHAR)malloc(dataSize);
	if (*Ciphertext == NULL) {
		HeapFree(GetProcessHeap(), 0, keyObject);
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return FALSE;
	}

	*CiphertextSize = dataSize;

	// Reset the IV copy because the first call to BCryptEncrypt alters the IV state
	memcpy(ivCopy, IV, AES_IV_SIZE);

	// PASS 2: Perform actual encryption into our newly allocated buffer
	status = BCryptEncrypt(
		hKey,
		Plaintext,
		PlaintextSize,
		NULL,
		ivCopy,
		AES_IV_SIZE,
		*Ciphertext,
		*CiphertextSize,
		&dataSize,
		BCRYPT_BLOCK_PADDING
	);

	HeapFree(GetProcessHeap(), 0, keyObject);
	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	return (status == 0);

}

void PrintHex(const char* Name, BYTE* Buffer, DWORD Size) {

	printf("\n%s:\n", Name);

	for (DWORD i = 0; i < Size; i++) {
		printf("%02X", Buffer[i]);
	}
	printf("\n");
}