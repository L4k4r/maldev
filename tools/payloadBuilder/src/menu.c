#include "glassBox.h"
#include "menu.h"

void PrintMenu(void)
{

	printf(
		".______      ___   ____    ____  __        ______        ___       _______  .______    __    __   __   __       _______   _______ .______      \n"
		"|   _  \\    /   \\  \\   \\  /   / |  |      /  __  \\      /   \\     |       \\ |   _  \\  |  |  |  | |  | |  |     |       \\ |   ____||   _  \\     \n"
		"|  |_)  |  /  ^  \\  \\   \\/   /  |  |     |  |  |  |    /  ^  \\    |  .--.  ||  |_)  | |  |  |  | |  | |  |     |  .--.  ||  |__   |  |_)  |    \n"
		"|   ___/  /  /_\\  \\  \\_    _/   |  |     |  |  |  |   /  /_\\  \\   |  |  |  ||   _  <  |  |  |  | |  | |  |     |  |  |  ||   __|  |      /     \n"
		"|  |     /  _____  \\   |  |     |  `----.|  `--'  |  /  _____  \\  |  '--'  ||  |_)  | |  `--'  | |  | |  `----.|  '--'  ||  |____ |  |\\  \\----.\n"
		"| _|    /__/     \\__\\  |__|     |_______| \\______/  /__/     \\__\\ |_______/ |______/   \\______/  |__| |_______||_______/ |_______|| _| `._____|\n"
	);


	printf("This program will encrypt and obfuscate the payload entered by the user.\n");
	printf("The encryption will be done with AES with a random 32 byte key and a random 16 byte IV.\n");
	printf("The user can chose what kind of obfuscation the program will use for the encrypted payload.\n\n");

	info("1 - Ipv4");
	info("2 - Ipv6");
	info("3 - MAC Address (COMING SOON)");
	info("4 - UUID (COMING SOON)\n");
}

int GetChoice(void) {

	int choice = 0;

	printf("Select obfuscation technique: ");
	scanf_s("%d", &choice);

	return choice;
}

static int HexCharToInt(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	return -1;
} 

BOOL ReadPayload(unsigned char** Payload, DWORD* PayloadSize) {

	char input[16384];

	printf("\n");
	okay("Enter payload in hex:\n");
	scanf_s("%16383s", input, (unsigned)sizeof(input));

	size_t len = strlen(input);

	if (len % 2 != 0){
		warn("Invaled hex string lenght (must be even)");
		return FALSE;
	}

	*PayloadSize = (DWORD)(len / 2);
	*Payload = malloc(*PayloadSize);

	if (*Payload == NULL) {
		warn("Allocation failed");
		return FALSE;
	}

	for (DWORD i = 0; i < *PayloadSize; i++)
	{
		int high = HexCharToInt(input[i * 2]);
		int low = HexCharToInt(input[i * 2 + 1]);

		if (high < 0 || low < 0) {
			warn("Invaled hex character");

			free(*Payload);
			*Payload = NULL;
			return FALSE;
		}

		(*Payload)[i] = (high << 4) | low;
	}

	return TRUE;

}