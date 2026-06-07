#include "encryption.h"
#include "obfuscation.h"
#include "glassBox.h"
#include "menu.h"

int main() {

	PrintMenu();

	int choice = GetChoice();

	// Read Payload
	unsigned char* payload = NULL;
	DWORD payloadSize = 0;

	if (!ReadPayload(&payload, &payloadSize)) {
		warn("Failed to read payload");
		return EXIT_FAILURE;
	}

	BYTE key[AES_KEY_SIZE];
	BYTE iv[AES_IV_SIZE];

	printf("\n");
	info("Generating random Key and IV ...");
	GenerateRandomBytes(key, sizeof(key));
	GenerateRandomBytes(iv, sizeof(iv));


	BYTE* encryptedPayload = NULL;
	DWORD encryptedSize = 0;

	if (!EncryptAES(
		payload,
		payloadSize,
		key,
		iv,
		&encryptedPayload,
		&encryptedSize
	)) {
		warn("Encryption failed!");
		free(payload);
		return FALSE;
	}

	PrintCArray("AESkey", key, 32);
	PrintCArray("AESIV", iv, 16);

	printf("\n");
	info("Encrypting payload ...");

	PrintHex("Encrypted input", encryptedPayload, encryptedSize);

	// Obfuscation
	switch(choice) {
	case 1:
		GenerateIpv4Output(encryptedPayload, encryptedSize);
		break;

	case 2:
		GenerateIpv6Output(encryptedPayload, encryptedSize);
		break;

	case 3:
		GenerateMacOutput(encryptedPayload, encryptedSize);
		break;

	default:
		warn("Invaled choice\n");
	}

	free(payload);
	free(encryptedPayload);

	in("Press <Enter> To Continue ...");

	return EXIT_SUCCESS;
}