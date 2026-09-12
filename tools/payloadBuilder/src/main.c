#include "encryption.h"
#include "obfuscation.h"
#include "glassBox.h"
#include "menu.h"

int main() {

	PrintMenu();


	// Read Payload
	unsigned char* payload = NULL;
	DWORD payloadSize = 0;

	if (!ReadPayload(&payload, &payloadSize)) {
		warn("Failed to read payload");
		return EXIT_FAILURE;
	}

	BYTE* encryptedPayload = NULL;
	DWORD encryptedSize = 0;

	// ==== Encryption ====
	int encChoice = GetEncryptionChoice();
	switch (encChoice) {

	case 1: {

		BYTE xorKey[XOR_KEY_SIZE];
		info("Generating random XOR key ...");
		GenerateRandomBytes(xorKey, sizeof(xorKey));

		XorRollingByInputKey(payload, payloadSize, xorKey, sizeof(xorKey));

		PrintCArray("XorKey", xorKey, sizeof(xorKey));

		encryptedPayload = payload;
		encryptedSize = payloadSize;
		payload = NULL;
		break;
	}

	case 2: {

		BYTE key[AES_KEY_SIZE];
		BYTE iv[AES_IV_SIZE];

		printf("\n");
		info("Generating random Key and IV ...");
		GenerateRandomBytes(key, sizeof(key));
		GenerateRandomBytes(iv, sizeof(iv));


		/*BYTE* encryptedPayload = NULL;
		DWORD encryptedSize = 0;*/

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
		break;

	}

	case 0: {
		info("Skipping encryption ...");
		encryptedPayload = payload;
		encryptedSize = payloadSize;
		payload = NULL;
		break;
	}

	default:
		warn("Invalid choice\n");
		free(payload);
		return EXIT_FAILURE;
	}


	PrintHex("[i] Encrypted input", encryptedPayload, encryptedSize);


	// Obfuscation
	int obfChoice = GetObfuscationChoice();

	switch(obfChoice) {
	case 1:
		GenerateIpv4Output(encryptedPayload, encryptedSize);
		break;

	case 2:
		GenerateIpv6Output(encryptedPayload, encryptedSize);
		break;

	case 3:
		GenerateMacOutput(encryptedPayload, encryptedSize);
		break;

	case 0: {
		info("Skipping obfuscation ...");
		PrintCArray("Payload", encryptedPayload, encryptedSize);
		break;
	}

	default:
		warn("Invalid choice\n");
	}

	free(payload);
	free(encryptedPayload);
	printf("\n");
	in("Press <Enter> To Continue ...");

	return EXIT_SUCCESS;
}