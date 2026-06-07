#include "glassBox.h"

// Function takes 4 raw bytes and returns them in an IPv4 string format
void GenerateIpv4(int a, int b, int c, int d, char* Output, size_t OutputSize) {

	snprintf(Output, OutputSize, "%d.%d.%d.%d", a, b, c, d);
}

BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	if (pShellcode == NULL || ShellcodeSize == 0) {
		warn("Payload is NULL");
		return EXIT_FAILURE;
	}

	//calculate padded size (next multiple of 4)
	SIZE_T PaddedSize = ShellcodeSize;

	while (PaddedSize % 4 != 0)
	{
		PaddedSize++;
	}


	// Allocate zero-initialzed buffer
	unsigned char* PaddedBuffer = calloc(PaddedSize, 1);

	if (PaddedBuffer == NULL) {
		warn("Failed to allocate padded buffer");
		return EXIT_FAILURE;
	}

	// Copy original shellcode, any remaining bytes stay 0x00 because of calloc()
	memcpy(PaddedBuffer, pShellcode, ShellcodeSize);

	info("Payload size: %zu bytes", ShellcodeSize);
	info("Padded size: %zu bytes \n", PaddedSize);

	printf("\nchar* ipv4Array[] = {\n\t");

	int counter = 0;
	char IP[32];

	for (SIZE_T i = 0; i < PaddedSize; i += 4) {
		counter++;

		GenerateIpv4(
			PaddedBuffer[i],
			PaddedBuffer[i + 1],
			PaddedBuffer[i + 2],
			PaddedBuffer[i + 3],
			IP,
			sizeof(IP)
		);

		if (i == PaddedSize - 4)
			printf("\"%s\"", IP);

		else
			printf("\"%s\",", IP);

		if (counter % 8 == 0)
			printf("\n\t");

	}

	printf("\n};\n\n");
	free(PaddedBuffer);
	return EXIT_SUCCESS;
}

// Function takes in 16 raw bytes and returns them in an IPv6 address string format
void GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p, char* Output, SIZE_T OutputSize) {

	snprintf(
		Output,
		OutputSize,
		"%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
		"%02X%02X:%02X%02X:%02X%02X:%02X%02X",
		a, b, c, d,
		e, f, g, h,
		i, j, k, l,
		m, n, o, p);
}

BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	if (pShellcode == NULL || ShellcodeSize == 0) {
		warn("Payload is NULL");
		return EXIT_FAILURE;
	}

	//calculate padded size (next multiple of 16)
	SIZE_T PaddedSize = ShellcodeSize;

	while (PaddedSize % 16 != 0)
	{
		PaddedSize++;
	}

	// Allocate zero-initialzed buffer
	unsigned char* PaddedBuffer = calloc(PaddedSize, 1);

	if (PaddedBuffer == NULL) {
		warn("Failed to allocate padded buffer");
		return EXIT_FAILURE;
	}

	memcpy(PaddedBuffer, pShellcode, ShellcodeSize);

	info("Payload size: %zu bytes", ShellcodeSize);
	info("Padded size: %zu bytes \n", PaddedSize);

	printf("\nchar* ipv6Array[] = {\n\t");

	char IP[64];
	int counter = 0;

	for (SIZE_T i = 0; i < PaddedSize; i += 16)
	{
		counter++;

		GenerateIpv6(
			PaddedBuffer[i],
			PaddedBuffer[i + 1],
			PaddedBuffer[i + 2],
			PaddedBuffer[i + 3],

			PaddedBuffer[i + 4],
			PaddedBuffer[i + 5],
			PaddedBuffer[i + 6],
			PaddedBuffer[i + 7],

			PaddedBuffer[i + 8],
			PaddedBuffer[i + 9],
			PaddedBuffer[i + 10],
			PaddedBuffer[i + 11],

			PaddedBuffer[i + 12],
			PaddedBuffer[i + 13],
			PaddedBuffer[i + 14],
			PaddedBuffer[i + 15],

			IP,
			sizeof(IP)
		);

		if (i == PaddedSize - 16)
			printf("\"%s\"", IP);
		else
			printf("\"%s\", ", IP);

		if (counter % 3 == 0)
			printf("\n\t");
	}

	printf("\n};\n\n");

	free(PaddedBuffer);
	return EXIT_SUCCESS;
}


// Function takes 6 raw bytes and returns them in a MAC address string format
void GenerateMAC(int a, int b, int c, int d, int e, int f, char* Output, SIZE_T OutputSize) {

	// Creating the MAC address variable and saving it to the Output variable
	snprintf(Output, OutputSize,"%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a, b, c, d, e, f);

}

// Generate the MAC output representation of the payload
// Function requires a pointer or base addresss to the payload buffer and the size of the payload buffer
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	
	// If the shellcode is null or the size is not a multiple of 6, exit
	if (pShellcode == NULL || ShellcodeSize == NULL) {
		warn("Payload is NULL");
		return FALSE;
	}

	// Calculate padded size (next multiple of 6)
	SIZE_T PaddedSize = ShellcodeSize;

	while (PaddedSize % 6 != 0) {
		PaddedSize++;
	}

	// Allocate zero-initialized buffer
	unsigned char* PaddedBuffer = calloc(PaddedSize, 1);

	if (PaddedBuffer == NULL) {
		warn("Failed to allocate padded buffer");
		return FALSE;
	}

	// Copy orignal payload
	memcpy(PaddedBuffer, pShellcode, ShellcodeSize);

	info("Payload size: %zu bytes", ShellcodeSize);
	info("Padded size: %zu bytes", PaddedSize);
	printf("\nchar* MacArray [%d] = {\n\t", (int)(ShellcodeSize / 6));

	// Read one payload byte at a time, when the total is 6, begin generating the MAC address
	int counter = 0;
	char Mac[32];

	for (SIZE_T i = 0; i < PaddedSize; i += 6) {
		counter++;

		GenerateMAC(PaddedBuffer[i], PaddedBuffer[i + 1], PaddedBuffer[i + 2], PaddedBuffer[i + 3], PaddedBuffer[i + 4], PaddedBuffer[i + 5], Mac, sizeof(Mac));

		if (i == PaddedSize - 6)
			printf("\"%s\"", Mac);
		else
			printf("\"%s\",", Mac);
		
		if (counter % 6 == 0)
			printf("\n\t");
	}
	printf("\n};\n\n");
	free(PaddedBuffer);
	return TRUE;
}