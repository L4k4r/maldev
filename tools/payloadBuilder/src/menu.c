#include "glassBox.h"
#include "menu.h"

void PrintMenu(void)
{

	//printf(
	//	".______      ___   ____    ____  __        ______        ___       _______  .______    __    __   __   __       _______   _______ .______      \n"
	//	"|   _  \\    /   \\  \\   \\  /   / |  |      /  __  \\      /   \\     |       \\ |   _  \\  |  |  |  | |  | |  |     |       \\ |   ____||   _  \\     \n"
	//	"|  |_)  |  /  ^  \\  \\   \\/   /  |  |     |  |  |  |    /  ^  \\    |  .--.  ||  |_)  | |  |  |  | |  | |  |     |  .--.  ||  |__   |  |_)  |    \n"
	//	"|   ___/  /  /_\\  \\  \\_    _/   |  |     |  |  |  |   /  /_\\  \\   |  |  |  ||   _  <  |  |  |  | |  | |  |     |  |  |  ||   __|  |      /     \n"
	//	"|  |     /  _____  \\   |  |     |  `----.|  `--'  |  /  _____  \\  |  '--'  ||  |_)  | |  `--'  | |  | |  `----.|  '--'  ||  |____ |  |\\  \\----.\n"
	//	"| _|    /__/     \\__\\  |__|     |_______| \\______/  /__/     \\__\\ |_______/ |______/   \\______/  |__| |_______||_______/ |_______|| _| `._____|\n"
	//);


	printf("\n\n"
		"\t8 8 8 8                     ,ooo.\n"
		"\t 8a8 8a8                    oP   ?b\n"
		"\td888a888zzzzzzzzzzzzzzzzzzzz8     8b\n"
		"\t     `""^""'                    ?o___oP'\n"
	);

	printf("\nThis program will encrypt and obfuscate the payload entered by the user.\n");
	printf("The user can choose the encryption method and the obfucsation technique.\n\n");


}


int GetEncryptionChoice(void) {
	int choice = 0;

	printf("\n");
	warn("Encryption Methods Available");
	info("0 - None (skip encryption)");
	info("1 - XOR (Rolling Key)");
	info("2 - AES-256\n");
	

	in("Select encrpytion method: ");
	scanf_s("%d", &choice);

	return choice;
}

int GetObfuscationChoice(void) {
	int choice = 0;

	warn("Obfuscation Method Available");
	info("0 - None (skip obfuscation)");
	info("1 - Ipv4");
	info("2 - Ipv6");
	info("3 - MAC Address");
	info("4 - UUID (COMING SOON?)\n");
	
	in("Select obfuscation method: ");
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

	return EXIT_FAILURE;
} 

void PrintCArray(const char* Name, const BYTE* Buffer, SIZE_T Size) {
	printf("\nunsigned char %s[%zu] = {\n\t", Name, Size);

	for (SIZE_T i = 0; i < Size; i++) {
		printf("0x%02X", Buffer[i]);

		if (i != Size - 1)
			printf(", ");
		if ((i + 1) % 8 == 0 && i != Size - 1)
			printf("\n\t");
	}
	printf("\n};\n");
}

BOOL ReadPayload(unsigned char** Payload, DWORD* PayloadSize) {

	char input[16384];

	printf("\n");
	in("Enter payload in hex: \n");
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